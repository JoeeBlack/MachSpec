import Foundation
import XPC

// Helper to convert JSON (Any) to XPC
func xpc_from_json(_ json: Any) -> xpc_object_t? {
    if let dict = json as? [String: Any], let type = dict["type"] as? String, let value = dict["value"] {
        
        switch type {
        case "dictionary":
            let xdict = xpc_dictionary_create(nil, nil, 0)
            if let valDict = value as? [String: Any] {
                for (k, v) in valDict {
                    if let xval = xpc_from_json(v) {
                        xpc_dictionary_set_value(xdict, k, xval)
                    }
                }
            }
            return xdict
            
        case "array":
            let xarray = xpc_array_create(nil, 0)
            if let valArray = value as? [Any] {
                for item in valArray {
                    if let xitem = xpc_from_json(item) {
                        xpc_array_append_value(xarray, xitem)
                    }
                }
            }
            return xarray
            
        case "int64":
            if let val = value as? Int64 {
                return xpc_int64_create(val)
            } else if let val = value as? Int {
                return xpc_int64_create(Int64(val))
            }
            
        case "uint64":
             if let val = value as? UInt64 {
                return xpc_uint64_create(val)
            } else if let val = value as? Int {
                return xpc_uint64_create(UInt64(val))
            }
            
        case "string":
            if let val = value as? String {
                return xpc_string_create(val)
            }
            
        case "bool":
            if let val = value as? Bool {
                return xpc_bool_create(val)
            }
            
        case "uuid":
            if let str = value as? String, let uuid = UUID(uuidString: str) {
                var uuidBytes = uuid.uuid
                return withUnsafePointer(to: &uuidBytes) { ptr in
                    // Need raw pointer to bytes
                    return ptr.withMemoryRebound(to: UInt8.self, capacity: 16) {
                        xpc_uuid_create($0)
                    }
                }
            }
            
        case "data":
             if let str = value as? String, let data = Data(base64Encoded: str) {
                 return data.withUnsafeBytes { ptr in
                     return xpc_data_create(ptr.baseAddress!, data.count)
                 }
             }

        default:
            return nil
        }
    }
    return nil
}

func main() {
    let args = CommandLine.arguments
    if args.count < 2 {
        print("Usage: XPCClient <service_name>")
        exit(1)
    }
    
    let serviceName = args[1]
    
    // Read JSON from stdin
    let inputData = FileHandle.standardInput.readDataToEndOfFile()
    
    guard let json = try? JSONSerialization.jsonObject(with: inputData, options: []) else {
        print("Error: Invalid JSON input")
        exit(1)
    }
    
    guard let xpcMessage = xpc_from_json(json) else {
        print("Error: Could not convert JSON to XPC")
        exit(1)
    }
    
    // Connect
    let connection = xpc_connection_create_mach_service(serviceName, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
    
    xpc_connection_set_event_handler(connection) { event in
        if event === XPC_ERROR_CONNECTION_INVALID {
             print("Error: Connection invalid")
             exit(1)
        }
        if event === XPC_ERROR_CONNECTION_INTERRUPTED {
             print("Error: Connection interrupted")
             exit(1)
        }
    }
    
    xpc_connection_resume(connection)
    
    // Send message
    // We use send_message_with_reply_sync for fuzzing usually to wait for result or crash
    let reply = xpc_connection_send_message_with_reply_sync(connection, xpcMessage)
    
    // reply is not optional in Swift mapping, it returns an object (which might be XPC_TYPE_ERROR)
    if xpc_get_type(reply) == XPC_TYPE_ERROR {
        print("XPC Error: \(reply)")
    } else {
        let desc = xpc_copy_description(reply)
        // desc is UnsafeMutablePointer<CChar> (not optional based on error)
        let str = String(cString: desc)
        print("Reply: \(str)")
        free(desc)
    }
}

main()
