// Public process vocabulary. Never publish raw API errors, names, or card UIDs.
export const processMessages: Record<string, string> = {
  idle: 'Standby Monitor',
  scan_student: 'Tap Student ID',
  checking_student: 'Checking student card',
  scan_item: 'Tap Equipment Tag',
  checking_item: 'Checking equipment tag',
  wrong_tag: 'Student card tapped again; tap the equipment tag',
  confirm: 'Press SCAN to confirm; MENU cancels',
  saving: 'Saving transaction; please wait',
  retry_confirm: 'Transaction not saved; press SCAN to retry or MENU to cancel',
  cancelled: 'Transaction cancelled; no record saved',
  success: 'Transaction Complete',
  error: 'Transaction Not Accepted',
}
export const publicErrors = new Set([
  'student_unknown', 'item_unknown', 'already_borrowed', 'wrong_borrower',
  'bad_uid', 'clock_skew', 'auth_failed', 'replay', 'request_reused',
  'server_error', 'bridge_offline', 'api_unreachable', 'unknown',
])
export function parseProcessBody(body: unknown): { mode: 'borrow' | 'return'; stage: string; error_code: string | null } | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const value = body as Record<string, unknown>
  if (Object.keys(value).some(key => !['mode', 'stage', 'error_code'].includes(key))) return null
  if (value.mode !== 'borrow' && value.mode !== 'return') return null
  if (typeof value.stage !== 'string' || !Object.hasOwn(processMessages, value.stage)) return null
  const error = value.error_code ?? null
  if (error !== null && (typeof error !== 'string' || !publicErrors.has(error) || !['error', 'retry_confirm'].includes(value.stage))) return null
  return { mode: value.mode, stage: value.stage, error_code: error as string | null }
}
