import struct
from lupa import LuaRuntime

def parse_perf_title_data(data):
    # parse date in this format into a dict
    # 1\x001847\x002\x00System\x004\x00Memory\x00
    data_table = {}
    elems = data.split('\x00')
    for i in range(0, len(elems), 2):
        #print(elems[i] + " " + elems[i+1])
        # dict items are in pairs
        data_table[elems[i+1]] = elems[i]
    return data_table



def parse_perf_data_block(data, pos):
    result = {}

    # Parse the signature
    result['Signature'] = data[pos:pos+4].decode('utf-16le').rstrip('\x00')
    pos += 4
    if result['Signature'] != "PERF":
        return False, "MSRPC: PERF_DATA_BLOCK signature is missing or incorrect"

    # Parse LittleEndian
    result['LittleEndian'], = struct.unpack_from('<I', data, pos)
    pos += 4
    if result['LittleEndian'] != 1:
        return False, "MSRPC: PERF_DATA_BLOCK returned a non-understood endianness"

    # Parse other fields
    fields = 'Version Revision TotalByteLength HeaderLength NumObjectTypes DefaultObject'
    fields_format = '<IIIIII'
    fields_values = struct.unpack_from(fields_format, data, pos)
    for field, value in zip(fields.split(), fields_values):
        result[field] = value
    pos += struct.calcsize(fields_format)

    # Parse SystemTime
    system_time_format = '<HHHHHHHH'  # SYSTEMTIME structure format
    result['SystemTime'] = struct.unpack_from(system_time_format, data, pos)
    pos += struct.calcsize(system_time_format)

    # Parse PerfTime, PerfFreq, PerfTime100nSec
    perf_fields = 'PerfTime PerfFreq PerfTime100nSec'
    perf_format = '<QQQ'
    perf_values = struct.unpack_from(perf_format, data, pos)
    for field, value in zip(perf_fields.split(), perf_values):
        result[field] = value
    pos += struct.calcsize(perf_format)

    pos += 4  # Skip misaligned bytes

    # Parse SystemNameLength and SystemNameOffset
    name_length_format = '<II'
    result['SystemNameLength'], result['SystemNameOffset'] = struct.unpack_from(name_length_format, data, pos)
    pos += struct.calcsize(name_length_format)

    if pos != result['SystemNameOffset'] + 1:
        return False, "MSRPC: PERF_DATA_BLOCK has SystemName in the wrong location"

    # Read SystemName
    result['SystemName'] = data[pos:pos+result['SystemNameLength']].decode('utf-16le')
    pos += result['SystemNameLength']

    pos += 4  # Adjust for misalignment

    return True, pos, result


def parse_perf_title_database_lua(data, pos):

    lua = LuaRuntime(unpack_returned_tuples=True)
    lua_func = lua.eval('''
function (data, pos)
  local result = {}
  local i = 1
  local string = require "string"

  repeat
    local number, name
    number, name, pos = string.unpack("<zz", data, pos)

    if(number == nil) then
      return false, "Couldn't parse the title database: end of string encountered early"
    elseif(tonumber(number) == nil) then -- Not sure if this actually happens, but it doesn't hurt to check
      return false, "Couldn't parse the title database"
    end

    result[tonumber(number)] = name
    i = i + 1
  until pos >= #data

  return true, pos, result
end''')

    status, pos, result = lua_func(data, pos)
    return status, pos, result
