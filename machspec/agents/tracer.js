/*
 * tracer.js - XPC Message Interceptor
 */

const xpc_connection_send_message = Module.findExportByName(null, "xpc_connection_send_message");
const xpc_connection_send_message_with_reply = Module.findExportByName(null, "xpc_connection_send_message_with_reply");
const xpc_connection_send_message_with_reply_sync = Module.findExportByName(null, "xpc_connection_send_message_with_reply_sync");

// Helper to parse XPC object to JSON string (if possible)
// Since we don't have a full XPC parser here easily without calling back to C func,
// we can try xpc_copy_description.
const xpc_copy_description = Module.findExportByName(null, "xpc_copy_description");
const free = Module.findExportByName(null, "free");

function describeXPC(xpcObj) {
    if (xpcObj.isNull()) return "null";
    const descPtr = new NativeFunction(xpc_copy_description, 'pointer', ['pointer'])(xpcObj);
    if (descPtr.isNull()) return "error(null_desc)";
    const str = descPtr.readUtf8String();
    new NativeFunction(free, 'void', ['pointer'])(descPtr);
    return str;
}

function handleMessage(conn, msg, funcName) {
    const msgStr = describeXPC(msg);
    const connStr = describeXPC(conn);

    send({
        type: "xpc_call",
        function: funcName,
        connection: connStr,
        message: msgStr
    });
}

if (xpc_connection_send_message) {
    Interceptor.attach(xpc_connection_send_message, {
        onEnter: function (args) {
            handleMessage(args[0], args[1], "xpc_connection_send_message");
        }
    });
}

if (xpc_connection_send_message_with_reply) {
    Interceptor.attach(xpc_connection_send_message_with_reply, {
        onEnter: function (args) {
            handleMessage(args[0], args[1], "xpc_connection_send_message_with_reply");
        }
    });
}

if (xpc_connection_send_message_with_reply_sync) {
    Interceptor.attach(xpc_connection_send_message_with_reply_sync, {
        onEnter: function (args) {
            handleMessage(args[0], args[1], "xpc_connection_send_message_with_reply_sync");
        }
    });
}
