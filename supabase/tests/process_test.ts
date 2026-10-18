import { parseProcessBody, processMessages } from '../functions/rfid-api/process.ts'

Deno.test('all public stages accept both modes, including legacy requests', () => {
  for (const stage of Object.keys(processMessages)) {
    for (const mode of ['borrow', 'return']) {
      if (!parseProcessBody({ mode, stage })) throw new Error(`Rejected ${mode}/${stage}`)
    }
  }
})
Deno.test('private text, invalid fields and misplaced error codes are rejected', () => {
  for (const body of [null, [], {}, { mode: 'bad', stage: 'idle' },
    { mode: 'borrow', stage: 'unknown' },
    { mode: 'borrow', stage: 'error', error_code: 'UID A1B2C3D4' },
    { mode: 'borrow', stage: 'idle', error_code: 'unknown' },
    { mode: 'borrow', stage: 'idle', student_uid: 'A1B2C3D4' }]) {
    if (parseProcessBody(body)) throw new Error('Accepted invalid process body')
  }
  if (!parseProcessBody({ mode: 'return', stage: 'retry_confirm', error_code: 'api_unreachable' })) {
    throw new Error('Rejected safe retry reason')
  }
})
