import type {Bot} from './bot'
import type {Inputs} from './inputs'
import type {Options} from './options'

export interface BugReport {
  description: string
  reproduction: string
  impact: string
  confidence: number // 0-100
  confidenceJustification: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  severityJustification: string
  suggestedFix: string
  filePath: string
  lineStart: number
  lineEnd: number
}

interface AnalysisResponse {
  analysis: {
    overview: string
    impactedAreas: string[]
    riskAssessment: string
  }
  bugReports: BugReport[]
}

export async function detectBugs(
  bot: Bot,
  inputs: Inputs,
  options: Options,
  filePath: string,
  fileContent: string,
  patch: string
): Promise<BugReport[]> {
  const bugDetectionPrompt = `## Context Analysis

File: \`${filePath}\`
Language/Framework: ${filePath.split('.').pop()}
PR Title: \`${inputs.title}\`

## Description
\`\`\`
${inputs.description}
\`\`\`

## Code Context
\`\`\`
${fileContent}
\`\`\`

## Changes
\`\`\`diff
${patch}
\`\`\`

## IMPORTANT: Bug Detection Instructions

You are an expert code reviewer specializing in detecting bugs and quality issues. Your task is to perform a thorough analysis of the code changes while maintaining a high standard of accuracy and minimizing false positives.

### Analysis Requirements

1. For each potential issue:
   - Provide concrete examples of how the bug manifests
   - Include specific conditions that trigger the issue
   - Explain the full impact and consequences
   - Detail why this is definitely a bug and not intended behavior
   - Consider if this could be a valid design decision

2. Code Understanding:
   - Analyze the broader context and purpose of the code
   - Consider the language/framework best practices
   - Evaluate architectural implications
   - Check for breaking changes in APIs/interfaces
   - Review test coverage implications

3. Validation Steps:
   - Verify the issue exists in the actual code (not theoretical)
   - Check if the issue is introduced by the changes
   - Validate that the suggested fix actually resolves the issue
   - Ensure the fix doesn't introduce new problems
   - Consider backward compatibility

### Focus Areas

1. Critical Logic Issues
   - Incorrect boolean logic or comparisons
   - Missing null/undefined checks with proven impact
   - Demonstrable race conditions
   - Proven memory leaks
   - Actual infinite loops
   - Documented data loss scenarios
   - Verifiable security vulnerabilities

2. Integration & Data Flow
   - Breaking API changes
   - Incorrect type handling
   - State management issues
   - Data transformation errors
   - Resource cleanup problems

3. Performance & Runtime
   - Significant performance impacts
   - Resource leaks
   - Blocking operations in critical paths
   - Proven scalability issues

### Confidence Scoring Criteria

Score confidence (0-100) based on these factors:
- 90-100: Definitive bug with clear reproduction steps
- 70-89: High probability issue with specific impact
- 50-69: Potential issue needing more context
- 0-49: Theoretical concern without clear proof

### Severity Guidelines

- critical: 
  - System crashes
  - Data corruption
  - Security breaches
  - Production outages
  
- high:
  - Frequent runtime errors
  - Data inconsistency
  - Major functionality breaks
  - Significant performance impact
  
- medium:
  - Edge case failures
  - Minor data issues
  - Degraded performance
  - UX problems
  
- low:
  - Code style issues
  - Minor inefficiencies
  - Non-critical improvements
  - Documentation needs

## Response Format

Return a valid JSON object with this structure:
{
  "analysis": {
    "overview": "High-level analysis of the changes",
    "impactedAreas": ["list", "of", "impacted", "systems"],
    "riskAssessment": "Overall risk evaluation"
  },
  "bugReports": [
    {
      "description": "Detailed bug description with concrete example",
      "reproduction": "Step-by-step reproduction steps",
      "impact": "Specific consequences of this bug",
      "confidence": <number 0-100>,
      "confidenceJustification": "Why this confidence score was chosen",
      "severity": "low" | "medium" | "high" | "critical",
      "severityJustification": "Why this severity level was chosen",
      "suggestedFix": "The exact code that should replace the buggy code. Do not include explanatory text - only include the actual code that should be used to fix the bug. The code must be properly formatted and indented.",
      "lineStart": <number>,
      "lineEnd": <number>
    }
  ]
}

## Important Guidelines

1. Quality Standards:
   - Only report issues with concrete evidence
   - For suggestedFix, provide ONLY the exact replacement code
   - The suggestedFix must be valid, compilable code
   - Maintain exact indentation in suggestedFix
   - Focus on significant issues

2. False Positive Prevention:
   - Verify each issue thoroughly
   - Consider valid design patterns
   - Check for intentional behavior
   - Validate fix effectiveness
   - Consider context and constraints

3. Response Requirements:
   - Return valid JSON only
   - No markdown or formatting in suggestedFix
   - No natural language in fixes
   - Empty bugReports for no issues
   - Complete all required fields

4. Code Fix Requirements:
   - suggestedFix must contain only the actual code to replace the bug
   - No explanatory text or comments in suggestedFix
   - Maintain proper indentation and formatting
   - Fix must be complete and valid code
   - Fix must address the root cause of the bug

IMPORTANT: Return ONLY valid JSON. No other text, no markdown, no code blocks.`

  try {
    const [response] = await bot.chat(bugDetectionPrompt, {})

    if (!response || !response.trim()) {
      if (options.debug) {
        console.warn('Bug detector received empty response')
      }
      return []
    }

    try {
      // Log the raw response for debugging
      if (options.debug) {
        // eslint-disable-next-line no-console
        console.debug('Raw bot response:', response)
      }

      // Extract the text content from various response formats
      let textToProcess = response
      if (typeof response === 'object' && response !== null) {
        interface MessageResponse {
          message?: {content?: string}
          text?: string
          detail?: {choices?: Array<{message?: {content?: string}}>}
        }

        const typedResponse = response as MessageResponse
        if (typedResponse.message?.content) {
          textToProcess = typedResponse.message.content
        } else if (typedResponse.text) {
          textToProcess = typedResponse.text
        } else if (typedResponse.detail?.choices?.[0]?.message?.content) {
          textToProcess = typedResponse.detail.choices[0].message.content
        } else {
          if (options.debug) {
            console.error('Unexpected response format:', response)
          }
          return []
        }
      }

      // Strip any markdown code block syntax before parsing
      textToProcess = textToProcess
        .trim()
        .replace(/^```(?:json)?\n/, '') // Remove opening code block
        .replace(/\n```$/, '') // Remove closing code block
        .trim()

      // Parse the response as JSON
      const parsedResponse = JSON.parse(textToProcess)

      // Log the analysis for debugging
      if (options.debug) {
        // eslint-disable-next-line no-console
        console.debug('Analysis:', parsedResponse.analysis)
      }

      // Return the bug reports
      const bugReports = parsedResponse.bugReports || []

      // Validate each report has required fields and proper code formatting
      const validReports = bugReports.filter((report: BugReport) => {
        const isValid =
          typeof report.description === 'string' &&
          typeof report.reproduction === 'string' &&
          typeof report.impact === 'string' &&
          typeof report.confidence === 'number' &&
          report.confidence >= 0 &&
          report.confidence <= 100 &&
          typeof report.confidenceJustification === 'string' &&
          ['low', 'medium', 'high', 'critical'].includes(report.severity) &&
          typeof report.severityJustification === 'string' &&
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
      if (options.debug) {
        console.error('Failed to parse bug detector response:', error)
        console.error('Raw response:', response)
      }
      return []
    }
  } catch (error) {
    if (options.debug) {
      console.error('Error during bug detection:', error)
    }
    return []
  }
}
