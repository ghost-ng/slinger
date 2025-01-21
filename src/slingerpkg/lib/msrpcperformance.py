import re
import struct
import sys
from datetime import datetime, timezone
from slingerpkg.utils.printlib import *

# this was a pain in the ass - I was inspired from the nmap script for this, a lot had to change because of 32bit vs 64bit
#https://svn.nmap.org/nmap/scripts/smb-enum-processes.nse
#https://learn.microsoft.com/en-us/windows/win32/api/winperf/
#https://svn.nmap.org/nmap/nselib/msrpcperformance.lua

"""
PERF_DATA_BLOCK
|
|--> PERF_OBJECT_TYPE #1
    |
    |--> PERF_COUNTER_DEFINITION #1
    |--> PERF_COUNTER_DEFINITION #2
    |    ...
    |--> PERF_COUNTER_DEFINITION #N
    |
    |--> (If no instances)
    |    |
    |    |--> PERF_COUNTER_BLOCK 
    |         |
    |         |--> Raw Counter Data for Counter #1
    |         |--> Raw Counter Data for Counter #2
    |         |    ...
    |         |--> Raw Counter Data for Counter #N
    |
    |--> (If instances exist)
         |
         |--> PERF_INSTANCE_DEFINITION #1
         |    |
         |    |--> Instance Name #1
         |    |--> PERF_COUNTER_BLOCK #1
         |         |
         |         |--> Raw Counter Data for Counter #1
         |         |--> Raw Counter Data for Counter #2
         |         |    ...
         |         |--> Raw Counter Data for Counter #N
         |
         |--> PERF_INSTANCE_DEFINITION #2
         |    ...
         |--> PERF_INSTANCE_DEFINITION #M
              |
              |--> Instance Name #M
              |--> PERF_COUNTER_BLOCK #M
                   |
                   |--> Raw Counter Data for Counter #1
                   |--> Raw Counter Data for Counter #2
                   |    ...
                   |--> Raw Counter Data for Counter #N
"""

def parse_perf_counter_data(data, pos, counter_definition):
    print_debug("Counter Size: " + str(counter_definition['CounterSize']))
    try:
        # Define format strings
        int32_fmt = '<I'  # 32-bit unsigned integer
        int64_fmt = '<Q'  # 64-bit unsigned integer

        result = None

        # Read the counter value based on its size
        if counter_definition['CounterSize'] == 4:
            # 4-byte counter
            result, pos = struct.unpack_from(int32_fmt, data, pos)[0], pos + 4
        elif counter_definition['CounterSize'] == 8:
            # 8-byte counter
            result, pos = struct.unpack_from(int64_fmt, data, pos)[0], pos + 8
        else:
            # If the counter size is neither 4 nor 8 bytes, we read it as raw bytes
            end_pos = pos + counter_definition['CounterSize']
            result = data[pos:end_pos]
            pos = end_pos

        return True, pos, result
    except struct.error as e:
        print_debug("MSRPC: ERROR: Error unpacking data: {}".format(e), sys.exc_info())
        return False, "Error unpacking data", None


def parse_perf_instance_definition(data, pos=0):        # no need for 64 bit handling
    result = {}
    initial_pos = pos
    pos, result['ByteLength']             = unmarshall_int32(data, pos)
    pos, result['ParentObjectTitleIndex'] = unmarshall_int32(data, pos)
    pos, result['ParentObjectInstance']   = unmarshall_int32(data, pos)
    pos, result['UniqueID']               = unmarshall_int32(data, pos)
    pos, result['NameOffset']             = unmarshall_int32(data, pos)
    pos, result['NameLength']             = unmarshall_int32(data, pos)
    
    # Calculate the position of the instance name
    name_start = initial_pos + result['NameOffset']
    name_end = name_start + result['NameLength']


    pos = initial_pos + result['ByteLength']
    # align to 8-byte boundary
    pos += (8 - pos % 8) % 8

    if name_end > len(data):
        result['InstanceName'] = "Instance name goes beyond data length"
        return False, pos, result
    
    
    try:
        result['InstanceName'] = data[name_start:name_end].decode('utf-16le').rstrip('\x00')
        return True, pos, result
    except UnicodeDecodeError:
        try:
            result['InstanceName'] = data[name_start:name_end].decode('utf-16le', errors='ignore').rstrip('\x00')
        except UnicodeDecodeError:
            print_debug("MSRPC: ERROR: Error decoding instance name")
            result['InstanceName'] = "Instance name contains invalid characters"
        return False, pos, result
    
    

def parse_perf_title_database(data, pos=0):     #validated
    #print(data)
    result = {}
    split_data = data.split('\x00')[2:]
     # Iterate over the list in steps of 2
    for i in range(0, len(split_data), 2):
        if i + 1 >= len(split_data):
            break
        number = split_data[i]
        name = split_data[i + 1]

        # Convert number to integer if needed
        try:
            number_key = int(number)
        except ValueError:
           continue

        # Store the pair in the dictionary
        result[number_key] = name

    return True, pos, result


def parse_perf_counter_definition(data, pos=0, is_64bit=False):            # need to do 64 bit handling
    try:
        # Define format strings for DWORD (32-bit unsigned integer) and LONG (32-bit signed integer)
        dword_fmt = '<I'
        long_fmt = '<l'

        # Initialize the counter definition dictionary
        counter_def = {}

        # Unpack fields strictly in the order they appear in the struct
        counter_def['ByteLength'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        counter_def['CounterNameTitleIndex'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        if is_64bit:
            counter_def['CounterNameTitle'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        else:
            pos += 4  # Skip LPWSTR pointer in 32-bit systems

        counter_def['CounterHelpTitleIndex'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        if is_64bit:
            counter_def['CounterHelpTitle'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        else:
            pos += 4  # Skip LPWSTR pointer in 32-bit systems

        counter_def['DefaultScale'], pos = struct.unpack_from(long_fmt, data, pos)[0], pos + 4
        counter_def['DetailLevel'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        counter_def['CounterType'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        counter_def['CounterSize'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        counter_def['CounterOffset'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        return True, pos, counter_def
    except struct.error as e:
        print_debug("MSRPC: ERROR: Error unpacking data: {}".format(e), sys.exc_info())
        return False, "Error unpacking data: " + str(e), None




def parse_perf_object_type(data, pos=0, is_64bit=False):
    try:
        # Define format strings for DWORD and LONG
        dword_fmt = '<I'
        long_fmt = '<l'
        large_integer_fmt = '<Q'  # LARGE_INTEGER is a 64-bit integer

        # Initialize the object type dictionary
        object_type = {}

        # Unpack fields strictly in the order they appear in the struct
        # Unpack DWORD fields
        for field in ['TotalByteLength', 'DefinitionLength', 'HeaderLength', 'ObjectNameTitleIndex']:
            object_type[field], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        # 64-bit systems have additional DWORDs instead of LPWSTR pointers
        if is_64bit:
            object_type['ObjectNameTitle'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        else:
            # Skip LPWSTR pointer in 32-bit systems (4 bytes)
            pos += 4

        for field in ['ObjectHelpTitleIndex']:
            object_type[field], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        if is_64bit:
            object_type['ObjectHelpTitle'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        else:
            # Skip LPWSTR pointer in 32-bit systems (4 bytes)
            pos += 4

        # Unpack remaining fields in the strict order
        object_type['DetailLevel'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        object_type['NumCounters'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        object_type['DefaultCounter'], pos = struct.unpack_from(long_fmt, data, pos)[0], pos + 4
        object_type['NumInstances'], pos = struct.unpack_from(long_fmt, data, pos)[0], pos + 4
        object_type['CodePage'], pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
        object_type['PerfTime'], pos = struct.unpack_from(large_integer_fmt, data, pos)[0], pos + 8
        object_type['PerfFreq'], pos = struct.unpack_from(large_integer_fmt, data, pos)[0], pos + 8

        return True, pos, object_type
    except struct.error as e:
        print_debug("MSRPC: ERROR: Error unpacking data: {}".format(e), sys.exc_info())
        return False, "Error unpacking data: " + str(e), None



def parse_perf_counter_block(data, pos=0):      # no need for 64 bit handling
    # Define format string for DWORD (32-bit unsigned integer)
    dword_fmt = '<I'  # Little-endian format

    try:
        # Unpack the ByteLength field
        byte_length, pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4

        return True, pos, {'ByteLength': byte_length}
    except struct.error as e:
        print_debug("MSRPC: ERROR: Error unpacking data: {}".format(e), sys.exc_info())
        return False, "Error unpacking data: {}".format(e), None

def parse_perf_title_database(data, pos=0):     #validated
    #print(data)
    result = {}
    split_data = data.split('\x00')[2:]
     # Iterate over the list in steps of 2
    for i in range(0, len(split_data), 2):
        if i + 1 >= len(split_data):
            break
        number = split_data[i]
        name = split_data[i + 1]

        # Convert number to integer if needed
        try:
            number_key = int(number)
        except ValueError:
           continue

        # Store the pair in the dictionary
        result[number_key] = name

    return True, pos, result

def parse_perf_counter_block_test(data, pos=0):
    dword_fmt = '<I'  # Little-endian format for DWORD

    try:
        byte_length, pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
    except struct.error as e:
        # Check if the buffer is too short for unpacking
        required_length = pos + 4  # Needed length for DWORD
        if len(data) < required_length:
            padding_needed = required_length - len(data)
            # Pad the data appropriately
            data += b'\x00' * padding_needed
            # Try unpacking again
            try:
                byte_length, pos = struct.unpack_from(dword_fmt, data, pos)[0], pos + 4
            except struct.error as e:
                # Handle error if unpacking still fails
                print_debug(f"MSRPC: ERROR: Error unpacking data after padding: {e}", sys.exc_info())
                return False, "Error unpacking data after padding", None
        else:
            # Handle other unpacking errors
            print_debug(f"MSRPC: ERROR: Error unpacking data: {e}", sys.exc_info())
            return False, "Error unpacking data", None

    return True, pos, {'ByteLength': byte_length}

def remove_null_terminator(s):
    # Remove common null terminator patterns from the end of the string
    return re.sub(r'(\x00|\\0)$', '', s)

def unicode_to_string(buffer, pos=0, length=None, do_null=False):
    """
    Read a unicode string from a buffer, optionally remove the null terminator,
    and optionally align it to a 4-byte boundary.

    Parameters:
    buffer (bytes): The buffer to read from.
    pos (int): The position in the buffer to start reading.
    length (int): The number of Unicode characters to read.
    do_null (bool): Whether to remove a null terminator from the string.

    Returns:
    (int, str): The new position and the string read.
    """

    if length is None:
        raise ValueError("Length must be provided")

    # Calculate end position in bytes, considering each Unicode character is 2 bytes
    endpos = pos + length * 2

    if endpos > len(buffer):
        print_debug(f"MSRPC: ERROR: Ran off the end of a string in unicode_to_string(), "
              f"this likely means we are reading a packet incorrectly. "
              f"(pos = {pos}, len(buffer) = {len(buffer)}, endpos = {endpos})")
        return None, None

    # Decode UTF-16 to a Python string
    str_ = buffer[pos:endpos].decode('utf-16le')

    if do_null:
        # Remove the null terminator if present
        str_ = str_.rstrip('\x00')

    # Align to 4-byte boundary
    endpos += (4 - (endpos % 4)) % 4

    return endpos, str_

def unmarshall_int64(data, pos=0):
    #print("MSRPC: Entering unmarshall_int64()")

    if len(data) - pos + 1 < 8:  # Check for sufficient bytes
        print_debug(f"MSRPC: ERROR: Ran off the end of a packet in unmarshall_int64(). {len(data)} - {pos} + 1 < 4")
        return pos, None

    # Unpack a 64-bit signed integer from the data
    format_string = "<q"
    value = struct.unpack_from(format_string, data, pos)[0]

    # Update position for the next read
    pos += 8

    #print("MSRPC: Leaving unmarshall_int64()")
    return pos, value


def unmarshall_int32(data, pos=0):
    #print("MSRPC: Entering unmarshall_int32()")

    if len(data) - pos + 1 < 4:  # Check for sufficient bytes
        print_debug(f"MSRPC: ERROR: Ran off the end of a packet in unmarshall_int32(). {len(data)} - {pos} + 1 < 4")
        #return pos, None

    # Unpack a 32-bit unsigned integer from the data
    format_string = "<I"
    value = struct.unpack_from(format_string, data, pos)[0]

    # Update position for the next read
    pos += 4

    #print("MSRPC: Leaving unmarshall_int32()")
    return pos, value


def unmarshall_SYSTEMTIME(data, pos=0):      # no need for 64 bit handling
    print_debug("MSRPC: Entering unmarshall_SYSTEMTIME()")

    fmt = '<H H H H H H H H'  # Equivalent format string for unpacking
    expected_length = struct.calcsize(fmt)

    # Check if there is enough data left to unpack
    if len(data) - pos < expected_length:
        print_debug("MSRPC: ERROR: Ran off the end of a packet in unmarshall_SYSTEMTIME().")
        return pos, None

    # Unpack the data
    unpacked_data = struct.unpack_from(fmt, data, pos)
    pos += expected_length

    # Create a dictionary to hold date components
    date = {
        'year': unpacked_data[0],
        'month': unpacked_data[1],
        'day': unpacked_data[3],
        'hour': unpacked_data[4],
        'minute': unpacked_data[5],
        'second': unpacked_data[6],
        'microsecond': unpacked_data[7] * 1000  # Convert milliseconds to microseconds
    }

    # Convert to a datetime object and then to a Unix timestamp
    date_obj = datetime(**date)
    timestamp = datetime.timestamp(date_obj)

    # print timestamp as string
    print_debug("TIME STAMP: " + datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
    print_debug("MSRPC: Leaving unmarshall_SYSTEMTIME()")

    return pos, timestamp

def parse_perf_data_block(data, pos=0):         # no need for 64 bit handling
    print_debug("MSRPC: Entering parse_perf_data_block()")
    result = {}

    # Assuming msrpctypes.unicode_to_string and msrpctypes.unmarshall_int32 are available in Python
    pos, result['Signature'] = unicode_to_string(data, pos, 4, False)
    if result['Signature'] != "PERF":
        print_debug("MSRPC: PERF_DATA_BLOCK signature is missing or incorrect")
        return False, "MSRPC: PERF_DATA_BLOCK signature is missing or incorrect"

    pos, result['LittleEndian'] = unmarshall_int32(data, pos)
    if result['LittleEndian'] != 1:
        print_debug("MSRPC: PERF_DATA_BLOCK returned a non-understood endianness")
        return False, "MSRPC: PERF_DATA_BLOCK returned a non-understood endianness"

    # Parse the header
    pos, result['Version']         = unmarshall_int32(data, pos)
    pos, result['Revision']        = unmarshall_int32(data, pos)
    pos, result['TotalByteLength'] = unmarshall_int32(data, pos)
    pos, result['HeaderLength']    = unmarshall_int32(data, pos)
    pos, result['NumObjectTypes']  = unmarshall_int32(data, pos)
    pos, result['DefaultObject']   = unmarshall_int32(data, pos)
    pos, result['SystemTime']      = unmarshall_SYSTEMTIME(data, pos)
    pos, result['PerfTime']        = unmarshall_int64(data, pos)
    pos, result['PerfFreq']        = unmarshall_int64(data, pos)
    pos, result['PerfTime100nSec'] = unmarshall_int64(data, pos)
    pos += 4  # This value doesn't seem to line up, so add 4

    pos, result['SystemNameLength'] = unmarshall_int32(data, pos)
    pos, result['SystemNameOffset'] = unmarshall_int32(data, pos)

    # Ensure system name is directly after the header
    if pos != result['SystemNameOffset']:
        print_debug("MSRPC: PERF_DATA_BLOCK has SystemName in the wrong location")
        return False, "MSRPC: PERF_DATA_BLOCK has SystemName in the wrong location"

    # Read the system name
    pos, result['SystemName'] = unicode_to_string(data, pos, result['SystemNameLength'] // 2, True)     # this is actually correct, this is a lua-to-python-ism

    # Align to 4-byte boundary
    pos += (4 - pos % 4) % 4

    print_debug("MSRPC: Leaving parse_perf_data_block()")
    return True, pos, result


