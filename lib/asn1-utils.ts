export interface TLV {
  tag: number
  len: number
  valueStart: number
  end: number
}

export function readTLV(data: Uint8Array, offset: number): TLV {
  const tag = data[offset]
  let p = offset + 1
  let len: number

  if (data[p] & 0x80) {
    const numBytes = data[p] & 0x7f
    p++
    len = 0
    for (let i = 0; i < numBytes; i++) len = (len << 8) | data[p++]
  } else {
    len = data[p++]
  }

  return { tag, len, valueStart: p, end: p + len }
}

export function encodeTLV(tag: number, value: Uint8Array): Uint8Array {
  const len = value.length
  let lenEnc: number[]

  if (len < 128) {
    lenEnc = [len]
  } else if (len < 256) {
    lenEnc = [0x81, len]
  } else if (len < 65536) {
    lenEnc = [0x82, (len >> 8) & 0xff, len & 0xff]
  } else {
    lenEnc = [0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]
  }

  const result = new Uint8Array(1 + lenEnc.length + len)
  result[0] = tag
  result.set(lenEnc, 1)
  result.set(value, 1 + lenEnc.length)
  return result
}

// Walk first-level children of a SEQUENCE/EXPLICIT, call visitor for each.
// Returns early if visitor returns true.
export function walkChildren(
  data: Uint8Array,
  parent: TLV,
  visitor: (tlv: TLV, offset: number) => boolean | void,
) {
  let offset = parent.valueStart
  while (offset < parent.end) {
    const tlv = readTLV(data, offset)
    if (visitor(tlv, offset)) return
    offset = tlv.end
  }
}
