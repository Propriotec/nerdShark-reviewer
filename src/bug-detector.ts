import type {Bot} from './bot'
import type {Inputs} from './inputs'
import type {Options} from './options'
import path from 'node:path'
import fs from 'node:fs/promises'

export interface BugReport {
  description: string
  confidence: number // 0-100
  severity: 'low' | 'medium' | 'high' | 'critical'
  suggestedFix: string
  filePath: string
  lineStart: number
  lineEnd: number
}

export async function detectBugs(
  bot: Bot,
  inputs: Inputs,
  options: Options,
  filePath: string,
  fileContent: string,
  patch: string
): Promise<BugReport[]> {
  // Get related files for context
  const relatedFiles = await getRelatedFiles(filePath, options)
  const projectContext = await buildProjectContext(relatedFiles)
  
  const bugDetectionPrompt = `## GitHub PR Title

\`$title\` 

## Description

\`\`\`
$description
\`\`\`

## Project Context

${projectContext}

## File Context

File: \`${filePath}\`

\`\`\`
${fileContent}
\`\`\`

## Changes to Review

\`\`\`diff
${patch}
\`\`\`

## IMPORTANT Instructions

You are a highly skilled code reviewer focused on detecting potential bugs and issues. Your task is to thoroughly analyze the code changes for any bugs, issues, or problematic patterns that could cause problems.

Focus Areas:

1. Logic and Edge Cases
   - Off-by-one errors
   - Incorrect boolean conditions
   - Missing null/undefined checks
   - Array bounds issues
   - Incorrect loop termination
   - Race conditions in async code
   - Missing error handling
   - Unhandled edge cases
   - State management issues
   - Incorrect assumptions about input data

2. Integration Issues
   - Incorrect function parameter usage
   - Type mismatches
   - Breaking changes to interfaces/APIs
   - Inconsistent state updates
   - Missing or incorrect error propagation
   - Problems with how the changed code interacts with existing code

3. Runtime and Performance
   - Memory leaks
   - Infinite loops
   - Blocking operations
   - Inefficient algorithms
   - Resource cleanup issues
   - Unnecessary computations
   - Potential deadlocks

4. Data Flow and Security
   - Incorrect data transformations
   - Data loss scenarios
   - Race conditions
   - Inconsistent state
   - Missing validation
   - Security vulnerabilities

## Response Format

You must respond with a valid JSON object in this exact format:
{
  "analysis": "Your detailed analysis of the code and explanation of any issues found",
  "bugReports": [
    {
      "description": "Clear explanation of why this could cause problems",
      "confidence": <number 0-100>,
      "severity": "low" | "medium" | "high" | "critical",
      "suggestedFix": "The exact code that should replace the problematic lines, with proper indentation preserved",
      "lineStart": <line number>,
      "lineEnd": <line number>
    }
  ]
}

## Important Guidelines

- Focus on both obvious bugs AND subtle logic issues that could cause problems
- Consider all possible edge cases and execution paths
- For each bug, provide the exact code that should replace the problematic lines
- If the fix is to remove code, leave suggestedFix as an empty string
- Preserve the exact indentation and code style when suggesting fixes
- The fix should only include the specific lines that need to change
- Do not include natural language instructions in the suggestedFix
- If no bugs are found, provide your analysis explaining why and return an empty bugReports array
- Pay special attention to assumptions made about input data or system state
- Assign severity levels based on potential impact:
  - critical: Could cause system crashes, data loss, or security breaches
  - high: Likely to cause incorrect behavior in common scenarios
  - medium: Could cause issues in edge cases or specific conditions
  - low: Minor issues that are unlikely to cause serious problems

IMPORTANT: Return ONLY valid JSON. No other text, no markdown, no code blocks.`

  try {
    // Clean up the patch to ensure it's in a standard format
    const cleanedPatch = patch
      .replace(/---new_hunk---\n/g, '')
      .replace(/---old_hunk---\n/g, '')
      .trim()

    const [response] = await bot.chat(bugDetectionPrompt, {})

    if (!response || !response.trim()) {
      console.warn('Bug detector received empty response')
      return []
    }

    try {
      // Log the raw response for debugging
      if (options.debug) {
        console.debug('Raw bot response:', response)
      }

      // Extract the text content from various response formats
      let textToProcess = response
      if (typeof response === 'object' && response !== null) {
        interface MessageResponse {
          message?: { content?: string }
          text?: string
          detail?: { choices?: Array<{ message?: { content?: string } }> }
        }

        const typedResponse = response as MessageResponse
        if (typedResponse.message?.content) {
          textToProcess = typedResponse.message.content
        } else if (typedResponse.text) {
          textToProcess = typedResponse.text
        } else if (typedResponse.detail?.choices?.[0]?.message?.content) {
          textToProcess = typedResponse.detail.choices[0].message.content
        } else {
          console.error('Unexpected response format:', response)
          return []
        }
      }

      // Strip any markdown code block syntax before parsing
      textToProcess = textToProcess.trim()
        .replace(/^```(?:json)?\n/, '') // Remove opening code block
        .replace(/\n```$/, '')          // Remove closing code block
        .trim()

      // Parse the response as JSON
      const parsedResponse = JSON.parse(textToProcess)
      
      // Log the analysis for debugging
      if (options.debug) {
        console.debug('Analysis:', parsedResponse.analysis)
      }

      // Return the bug reports
      const bugReports = parsedResponse.bugReports || []
      
      // Validate each report has required fields and proper code formatting
      const validReports = bugReports.filter((report: BugReport) => {
        const isValid =
          typeof report.description === 'string' &&
          typeof report.confidence === 'number' &&
          report.confidence >= 0 &&
          report.confidence <= 100 &&
          ['low', 'medium', 'high', 'critical'].includes(report.severity) &&
          typeof report.suggestedFix === 'string' &&
          typeof report.lineStart === 'number' &&
          typeof report.lineEnd === 'number' &&
          report.lineStart <= report.lineEnd

        if (!isValid && options.debug) {
          console.warn('Invalid bug report:', report)
        }
        return isValid
      })

      return validReports.map((report: BugReport) => ({
        ...report,
        filePath
      }))
    } catch (error) {
      console.error('Failed to parse bug detector response:', error)
      if (options.debug) {
        console.error('Raw response:', response)
      }
      return []
    }
  } catch (error) {
    console.error('Error during bug detection:', error)
    return []
  }
}

// Helper function to get related files
async function getRelatedFiles(filePath: string, options: Options): Promise<Map<string, string>> {
  const relatedFiles = new Map<string, string>()
  
  try {
    // Get imports and dependencies from the file
    const fileImports = await extractImports(filePath)
    
    // Get files in the same directory
    const dirPath = path.dirname(filePath)
    const dirFiles = await fs.readdir(dirPath)
    
    // Add related files to the map
    for (const file of [...fileImports, ...dirFiles]) {
      if (options.checkPath(file)) {
        try {
          const content = await fs.readFile(file, 'utf8')
          relatedFiles.set(file, content)
        } catch (error) {
          console.warn(`Could not read file ${file}:`, error)
        }
      }
    }
  } catch (error) {
    console.warn('Error getting related files:', error)
  }
  
  return relatedFiles
}

// Helper function to build project context string
async function buildProjectContext(files: Map<string, string>): Promise<string> {
  let context = '### Related Files\n\n'
  
  for (const [file, content] of files.entries()) {
    context += `File: \`${file}\`\n\n\`\`\`\n${content}\n\`\`\`\n\n`
  }
  
  return context
}

// Helper function to extract imports from a file
async function extractImports(filePath: string): Promise<string[]> {
  const imports: string[] = []
  try {
    const content = await fs.readFile(filePath, 'utf8')
    
    // Extract TypeScript/JavaScript imports
    const importRegex = /import.*from\s+['"](.+)['"]/g
    let match: RegExpExecArray | null = null
    match = importRegex.exec(content)
    while (match) {
      if (match[1] && !match[1].startsWith('.')) {
        match = importRegex.exec(content)
        continue // Skip external imports
      }
      const importPath = path.resolve(path.dirname(filePath), match[1])
      imports.push(importPath)
      match = importRegex.exec(content)
    }
    
    // Extract require statements
    const requireRegex = /require\(['"](.+)['"]\)/g
    match = requireRegex.exec(content)
    while (match) {
      if (match[1] && !match[1].startsWith('.')) {
        match = requireRegex.exec(content)
        continue // Skip external imports
      }
      const importPath = path.resolve(path.dirname(filePath), match[1])
      imports.push(importPath)
      match = requireRegex.exec(content)
    }
  } catch (error) {
    console.warn(`Error extracting imports from ${filePath}:`, error)
  }
  
  return imports
}
