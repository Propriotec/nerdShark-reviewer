import type {Bot} from './bot'
import type {Inputs} from './inputs'
import type {Options} from './options'
import {debug, warning} from '@actions/core'

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
  const bugDetectionPrompt = `${options.systemMessage}

## Configuration Context
- Language: ${options.language}

## GitHub PR Title

\`${inputs.title}\` 

## Description

\`\`\`
${inputs.description}
\`\`\`

## File Information
- Filename: ${inputs.filename || filePath}
- Language: ${options.language}

## File Content Context
Original Content:
\`\`\`
${inputs.fileContent || fileContent}
\`\`\`

## Diff Information
File Diff Overview:
\`\`\`
${inputs.fileDiff || patch}
\`\`\`

Detailed Patches:
\`\`\`
${inputs.patches || '(No additional patch information available)'}
\`\`\`

Additional Diff Context:
\`\`\`
${
  inputs.diff !== 'no diff'
    ? inputs.diff
    : '(No additional diff context available)'
}
\`\`\`

## Review Context
${
  inputs.comment !== 'no comment provided'
    ? `
Current Comment:
\`\`\`
${inputs.comment}
\`\`\`
`
    : ''
}

## Comment Chain Context
${
  inputs.commentChain !== 'no other comments on this patch'
    ? `
Previous Comments:
\`\`\`
${inputs.commentChain}
\`\`\`
`
    : '(No previous comments on this patch)'
}

## Raw Summary
${
  inputs.rawSummary
    ? `
\`\`\`
${inputs.rawSummary}
\`\`\`
`
    : '(No raw summary available)'
}

## Short Summary
${
  inputs.shortSummary
    ? `
\`\`\`
${inputs.shortSummary}
\`\`\`
`
    : '(No short summary available)'
}

## Bug Detection Instructions

You are a specialized code analyzer focused on detecting potential bugs and issues. Your task is to analyze the code changes for bugs that could impact reliability, security, or correctness.

Review Strategy:
${
  options.reviewSimpleChanges
    ? '- Review all changes thoroughly, including simple ones'
    : '- Focus on complex changes and potential issues'
}
${
  options.reviewCommentLGTM
    ? '- Include LGTM comments for good code'
    : '- Skip LGTM comments for good code'
}

Context Analysis:
1. File Content Context
   - Analyze how changes interact with existing code structure
   - Consider imports, dependencies, and module relationships
   - Check for consistency with existing patterns and conventions
   - Verify changes maintain type safety and interface contracts

2. Diff Context
   - Examine changes in relation to surrounding code
   - Verify modifications preserve existing functionality
   - Check for unintended side effects on dependent code
   - Ensure changes handle all edge cases

3. PR Context
   - Consider the PR description and purpose
   - Review related comment chains for context
   - Check if changes align with PR objectives
   - Verify changes address any mentioned issues

Key Areas to Check:
1. Logic & Control Flow
   - Off-by-one errors
   - Incorrect boolean logic
   - Missing null/undefined checks
   - Improper error handling
   - Race conditions in async code
   - Incorrect assumptions about input data
   - State management issues

2. Data & Type Safety
   - Type mismatches
   - Unsafe type coercion
   - Missing data validation
   - Buffer overflows
   - Memory leaks
   - Breaking changes to interfaces/APIs
   - Incorrect function parameter usage

3. Security & Best Practices
   - Input validation gaps
   - SQL injection risks
   - XSS vulnerabilities
   - Insecure data exposure
   - Broken authentication
   - Resource cleanup issues
   - Potential deadlocks

Severity Guidelines:
- critical: System crash, data loss, security breach (e.g. SQL injection, auth bypass)
- high: Incorrect behavior in common cases (e.g. null pointer, type error)
- medium: Edge case failures (e.g. off-by-one, boundary condition)
- low: Code quality issues (e.g. memory inefficiency, minor logic flaw)

Response Format (JSON only):
{
  "bugReports": [
    {
      "description": "Clear explanation of the bug and its potential impact",
      "confidence": <0-100>,
      "severity": "low|medium|high|critical",
      "suggestedFix": "Exact replacement code that matches the codebase style",
      "lineStart": <number>,
      "lineEnd": <number>
    }
  ]
}

Guidelines:
- Focus on concrete bugs, not style issues
- Consider the full context including PR description and project files
- Analyze how changes interact with existing code
- Provide exact code fixes that match the codebase style
- Set confidence based on certainty of the bug
- Return empty bugReports if no bugs found
- Keep fixes minimal and targeted
- Pay special attention to security implications
- Consider edge cases and error conditions

IMPORTANT: Return ONLY valid JSON. No other text, no markdown, no code blocks.`

  try {
    // Clean up the patch to ensure it's in a standard format
    const cleanedPatch = patch
      .replace(/---new_hunk---\n/g, '')
      .replace(/---old_hunk---\n/g, '')
      .trim()

    const [response] = await bot.chat(
      bugDetectionPrompt.replace('${patch}', cleanedPatch),
      {}
    )

    if (!response || !response.trim()) {
      warning('Bug detector received empty response')
      return []
    }

    try {
      // Log the raw response for debugging
      if (options.debug) {
        debug(`Raw bot response: ${response}`)
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
          warning(`Unexpected response format: ${JSON.stringify(response)}`)
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
          warning(`Invalid bug report: ${JSON.stringify(report)}`)
        }
        return isValid
      })

      if (options.debug) {
        debug(`Found ${validReports.length} valid bug reports`)
      }

      return validReports.map((report: BugReport) => ({
        ...report,
        filePath
      }))
    } catch (error) {
      warning(`Failed to parse bug detector response: ${error}`)
      if (options.debug) {
        warning(`Raw response: ${response}`)
      }
      return []
    }
  } catch (error) {
    warning(`Error during bug detection: ${error}`)
    return []
  }
}
