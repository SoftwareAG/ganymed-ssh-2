package ch.ethz.ssh2;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.HashMap;
import java.util.Map;

import ch.ethz.ssh2.channel.Channel;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.sftp.AttribFlags;
import ch.ethz.ssh2.sftp.ErrorCodes;
import ch.ethz.ssh2.sftp.Packet;
import ch.ethz.ssh2.util.StringEncoder;

/**
 * @version $Id$
 */
public abstract class AbstractSFTPClient implements SFTPClient {

    private static final Logger log = Logger.getLogger(SFTPv3Client.class);

    private Session sess;

    private InputStream is;
    private OutputStream os;

    private int next_request_id = 1000;

    private String charset;

    /**
     * Parallel read requests maximum size.
     */
    private static final int DEFAULT_MAX_PARALLELISM = 64;

    /**
     * Parallel read requests.
     */
    private int parallelism = DEFAULT_MAX_PARALLELISM;

    public void setRequestParallelism(int parallelism) {
        this.parallelism = Math.min(parallelism, DEFAULT_MAX_PARALLELISM);
    }

    /**
     * Mapping request ID to request.
     */
    private Map<Integer, OutstandingReadRequest> pendingReadQueue
            = new HashMap<Integer, OutstandingReadRequest>();

    /**
     * Mapping request ID to request.
     */
    private Map<Integer, OutstandingStatusRequest> pendingStatusQueue
            = new HashMap<Integer, OutstandingStatusRequest>();

    private PacketListener listener;

    protected AbstractSFTPClient(final Connection conn, final int version, final PacketListener listener) throws IOException {
        this.listener = listener;

        log.debug("Opening session and starting SFTP subsystem.");
        sess = conn.openSession();
        sess.startSubSystem("sftp");

        is = sess.getStdout();
        os = new BufferedOutputStream(sess.getStdin(), 2048);

        init(version);

    }

    private void init(final int client_version) throws IOException {
        // Send SSH_FXP_INIT with client version

        TypesWriter tw = new TypesWriter();
        tw.writeUINT32(client_version);
        sendMessage(Packet.SSH_FXP_INIT, 0, tw.getBytes());

		/* Receive SSH_FXP_VERSION */

        log.debug("Waiting for SSH_FXP_VERSION...");
        TypesReader tr = new TypesReader(receiveMessage(34000)); /* Should be enough for any reasonable server */

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        if(t != Packet.SSH_FXP_VERSION) {
            log.warning(String.format("The server did not send a SSH_FXP_VERSION but %d", t));
            throw new PacketTypeException(t);
        }

        final int protocol_version = tr.readUINT32();

        log.debug("SSH_FXP_VERSION: protocol_version = " + protocol_version);
        if(protocol_version != client_version) {
            throw new IOException(String.format("Server protocol version %d does not match %d",
                    protocol_version, client_version));
        }
        // Both parties should from then on adhere to particular version of the protocol

        // Read and save extensions (if any) for later use
        while(tr.remain() != 0) {
            String name = tr.readString();
            listener.read(name);
            byte[] value = tr.readByteString();
            log.debug(String.format("SSH_FXP_VERSION: extension: %s = '%s'", name, StringEncoder.GetString(value)));
        }
    }

    /**
     * Queries the channel state
     *
     * @return True if the underlying session is in open state
     */
    @Override
    public boolean isConnected() {
        return sess.getState() == Channel.STATE_OPEN;
    }

    /**
     * Close this SFTP session. NEVER forget to call this method to free up
     * resources - even if you got an exception from one of the other methods.
     * Sometimes these other methods may throw an exception, saying that the
     * underlying channel is closed (this can happen, e.g., if the other server
     * sent a close message.) However, as long as you have not called the
     * <code>close()</code> method, you are likely wasting resources.
     */
    @Override
    public void close() {
        sess.close();
    }

    /**
     * Set the charset used to convert between Java Unicode Strings and byte encodings
     * used by the server for paths and file names.
     *
     * @param charset the name of the charset to be used or <code>null</code> to use UTF-8.
     * @throws java.io.IOException
     * @see #getCharset()
     */
    @Override
    public void setCharset(String charset) throws IOException {
        if(charset == null) {
            this.charset = null;
            return;
        }
        try {
            Charset.forName(charset);
        }
        catch(UnsupportedCharsetException e) {
            throw new IOException("This charset is not supported", e);
        }
        this.charset = charset;
    }

    /**
     * The currently used charset for filename encoding/decoding.
     *
     * @return The name of the charset (<code>null</code> if UTF-8 is used).
     * @see #setCharset(String)
     */
    @Override
    public String getCharset() {
        return charset;
    }

    public abstract SFTPFileHandle openFile(String fileName, int flags, SFTPFileAttributes attr) throws IOException;

    @Override
    public void mkdir(String dirName, int posixPermissions) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(dirName, this.getCharset());
        tw.writeUINT32(AttribFlags.SSH_FILEXFER_ATTR_PERMISSIONS);
        tw.writeUINT32(posixPermissions);

        sendMessage(Packet.SSH_FXP_MKDIR, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void rm(String fileName) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(fileName, this.getCharset());

        sendMessage(Packet.SSH_FXP_REMOVE, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void rmdir(String dirName) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(dirName, this.getCharset());

        sendMessage(Packet.SSH_FXP_RMDIR, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void mv(String oldPath, String newPath) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(oldPath, this.getCharset());
        tw.writeString(newPath, this.getCharset());

        sendMessage(Packet.SSH_FXP_RENAME, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public String readLink(String path) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(path, charset);

        sendMessage(Packet.SSH_FXP_READLINK, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_NAME) {
            int count = tr.readUINT32();

            if(count != 1) {
                throw new PacketTypeException(t);
            }

            return tr.readString(charset);
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    @Override
    public void setstat(String path, SFTPFileAttributes attr) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(path, charset);
        tw.writeBytes(attr.toBytes());

        sendMessage(Packet.SSH_FXP_SETSTAT, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void fsetstat(SFTPFileHandle handle, SFTPFileAttributes attr) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(handle.getHandle(), 0, handle.getHandle().length);
        tw.writeBytes(attr.toBytes());

        sendMessage(Packet.SSH_FXP_FSETSTAT, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void createSymlink(String src, String target) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(src, charset);
        tw.writeString(target, charset);

        sendMessage(Packet.SSH_FXP_SYMLINK, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void createHardlink(String src, String target) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString("hardlink@openssh.com", charset);
        tw.writeString(target, charset);
        tw.writeString(src, charset);

        sendMessage(Packet.SSH_FXP_EXTENDED, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public String canonicalPath(String path) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(path, charset);

        sendMessage(Packet.SSH_FXP_REALPATH, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_NAME) {
            int count = tr.readUINT32();

            if(count != 1) {
                throw new PacketFormatException("The server sent an invalid SSH_FXP_NAME packet.");
            }
            final String name = tr.readString(charset);
            listener.read(name);
            return name;
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    private void sendMessage(int type, int requestId, byte[] msg, int off, int len) throws IOException {
        if(log.isDebugEnabled()) {
            log.debug(String.format("Send message of type %d with request id %d", type, requestId));
        }
        listener.write(Packet.forName(type));

        int msglen = len + 1;

        if(type != Packet.SSH_FXP_INIT) {
            msglen += 4;
        }

        os.write(msglen >> 24);
        os.write(msglen >> 16);
        os.write(msglen >> 8);
        os.write(msglen);
        os.write(type);

        if(type != Packet.SSH_FXP_INIT) {
            os.write(requestId >> 24);
            os.write(requestId >> 16);
            os.write(requestId >> 8);
            os.write(requestId);
        }

        os.write(msg, off, len);
        os.flush();
    }

    protected void sendMessage(int type, int requestId, byte[] msg) throws IOException {
        sendMessage(type, requestId, msg, 0, msg.length);
    }

    private void readBytes(byte[] buff, int pos, int len) throws IOException {
        while(len > 0) {
            int count = is.read(buff, pos, len);
            if(count < 0) {
                throw new SocketException("Unexpected end of stream.");
            }
            len -= count;
            pos += count;
        }
    }

    /**
     * Read a message and guarantee that the <b>contents</b> is not larger than
     * <code>maxlen</code> bytes.
     * <p/>
     * Note: receiveMessage(34000) actually means that the message may be up to 34004
     * bytes (the length attribute preceding the contents is 4 bytes).
     *
     * @param maxlen
     * @return the message contents
     * @throws IOException
     */
    protected byte[] receiveMessage(int maxlen) throws IOException {
        byte[] msglen = new byte[4];

        readBytes(msglen, 0, 4);

        int len = (((msglen[0] & 0xff) << 24) | ((msglen[1] & 0xff) << 16) | ((msglen[2] & 0xff) << 8) | (msglen[3] & 0xff));

        if((len > maxlen) || (len <= 0)) {
            throw new PacketFormatException(String.format("Illegal SFTP packet length %d", len));
        }

        byte[] msg = new byte[len];

        readBytes(msg, 0, len);

        return msg;
    }

    protected int generateNextRequestID() {
        synchronized(this) {
            return next_request_id++;
        }
    }

    protected void closeHandle(byte[] handle) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(handle, 0, handle.length);

        sendMessage(Packet.SSH_FXP_CLOSE, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    private void readStatus() throws IOException {
        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);
        int t = tr.readByte();
        listener.read(Packet.forName(t));

        // Search the pending queue
        OutstandingStatusRequest status = pendingStatusQueue.remove(tr.readUINT32());
        if(null == status) {
            throw new RequestMismatchException();
        }

        // Evaluate the answer
        if(t == Packet.SSH_FXP_STATUS) {
            // In any case, stop sending more packets
            int code = tr.readUINT32();
            if(log.isDebugEnabled()) {
                String[] desc = ErrorCodes.getDescription(code);
                log.debug("Got SSH_FXP_STATUS (" + status.req_id + ") (" + ((desc != null) ? desc[0] : "UNKNOWN") + ")");
            }
            if(code == ErrorCodes.SSH_FX_OK) {
                return;
            }
            String msg = tr.readString();
            listener.read(msg);
            throw new SFTPException(msg, code);
        }
        throw new PacketTypeException(t);
    }

    private void readPendingReadStatus() throws IOException {
        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);
        int t = tr.readByte();
        listener.read(Packet.forName(t));

        // Search the pending queue
        OutstandingReadRequest status = pendingReadQueue.remove(tr.readUINT32());
        if(null == status) {
            throw new RequestMismatchException();
        }

        // Evaluate the answer
        if(t == Packet.SSH_FXP_STATUS) {
            // In any case, stop sending more packets
            int code = tr.readUINT32();
            if(log.isDebugEnabled()) {
                String[] desc = ErrorCodes.getDescription(code);
                log.debug("Got SSH_FXP_STATUS (" + status.req_id + ") (" + ((desc != null) ? desc[0] : "UNKNOWN") + ")");
            }
            if(code == ErrorCodes.SSH_FX_OK) {
                return;
            }
            if(code == ErrorCodes.SSH_FX_EOF) {
                return;
            }
            String msg = tr.readString();
            listener.read(msg);
            throw new SFTPException(msg, code);
        }
        throw new PacketTypeException(t);
    }

    protected void expectStatusOKMessage(int id) throws IOException {
        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != id) {
            throw new RequestMismatchException();
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();

        if(errorCode == ErrorCodes.SSH_FX_OK) {
            return;
        }
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    @Override
    public void closeFile(SFTPFileHandle handle) throws IOException {
        while(!pendingReadQueue.isEmpty()) {
            this.readPendingReadStatus();
        }
        while(!pendingStatusQueue.isEmpty()) {
            this.readStatus();
        }
        closeHandle(handle.getHandle());
    }

    @Override
    public int read(SFTPFileHandle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException {
        boolean errorOccured = false;
        int remaining = len * parallelism;
        //int clientOffset = dstoff;

        long serverOffset = fileOffset;
        for(OutstandingReadRequest r : pendingReadQueue.values()) {
            // Server offset should take pending requests into account.
            serverOffset += r.len;
        }

        while(true) {
            // Stop if there was an error and no outstanding request
            if((pendingReadQueue.size() == 0) && errorOccured) {
                break;
            }

            // Send as many requests as we are allowed to
            while(pendingReadQueue.size() < parallelism) {
                if(errorOccured) {
                    break;
                }
                // Send the next read request
                OutstandingReadRequest req = new OutstandingReadRequest();
                req.req_id = generateNextRequestID();
                req.serverOffset = serverOffset;
                req.len = (remaining > len) ? len : remaining;
                req.buffer = dst;
                req.dstOffset = dstoff;

                serverOffset += req.len;
                //clientOffset += req.len;
                remaining -= req.len;

                sendReadRequest(req.req_id, handle, req.serverOffset, req.len);

                pendingReadQueue.put(req.req_id, req);
            }
            if(pendingReadQueue.size() == 0) {
                break;
            }

            // Receive a single answer
            byte[] resp = receiveMessage(34000);
            TypesReader tr = new TypesReader(resp);

            int t = tr.readByte();
            listener.read(Packet.forName(t));

            // Search the pending queue
            OutstandingReadRequest req = pendingReadQueue.remove(tr.readUINT32());
            if(null == req) {
                throw new RequestMismatchException();
            }
            // Evaluate the answer
            if(t == Packet.SSH_FXP_STATUS) {
                /* In any case, stop sending more packets */

                int code = tr.readUINT32();
                String msg = tr.readString();
                listener.read(msg);

                if(log.isDebugEnabled()) {
                    String[] desc = ErrorCodes.getDescription(code);
                    log.debug("Got SSH_FXP_STATUS (" + req.req_id + ") (" + ((desc != null) ? desc[0] : "UNKNOWN") + ")");
                }
                // Flag to read all pending requests but don't send any more.
                errorOccured = true;
                if(pendingReadQueue.isEmpty()) {
                    if(ErrorCodes.SSH_FX_EOF == code) {
                        return -1;
                    }
                    throw new SFTPException(msg, code);
                }
            }
            else if(t == Packet.SSH_FXP_DATA) {
                // OK, collect data
                int readLen = tr.readUINT32();

                if((readLen < 0) || (readLen > req.len)) {
                    throw new PacketFormatException("The server sent an invalid length field in a SSH_FXP_DATA packet.");
                }

                if(log.isDebugEnabled()) {
                    log.debug("Got SSH_FXP_DATA (" + req.req_id + ") " + req.serverOffset + "/" + readLen
                            + " (requested: " + req.len + ")");
                }

                // Read bytes into buffer
                tr.readBytes(req.buffer, req.dstOffset, readLen);

                if(readLen < req.len) {
                    /* Send this request packet again to request the remaing data in this slot. */
                    req.req_id = generateNextRequestID();
                    req.serverOffset += readLen;
                    req.len -= readLen;

                    log.debug("Requesting again: " + req.serverOffset + "/" + req.len);
                    sendReadRequest(req.req_id, handle, req.serverOffset, req.len);

                    pendingReadQueue.put(req.req_id, req);
                }
                return readLen;
            }
            else {
                throw new PacketTypeException(t);
            }
        }
        // Should never reach here.
        throw new SFTPException("No EOF reached", -1);
    }

    private void sendReadRequest(int id, SFTPFileHandle handle, long offset, int len) throws IOException {
        TypesWriter tw = new TypesWriter();
        tw.writeString(handle.getHandle(), 0, handle.getHandle().length);
        tw.writeUINT64(offset);
        tw.writeUINT32(len);

        sendMessage(Packet.SSH_FXP_READ, id, tw.getBytes());
    }

    @Override
    public void write(SFTPFileHandle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException {
        while(len > 0) {
            int writeRequestLen = len;

            if(writeRequestLen > 32768) {
                writeRequestLen = 32768;
            }

            // Send the next write request
            OutstandingStatusRequest req = new OutstandingStatusRequest();
            req.req_id = generateNextRequestID();

            TypesWriter tw = new TypesWriter();
            tw.writeString(handle.getHandle(), 0, handle.getHandle().length);
            tw.writeUINT64(fileOffset);
            tw.writeString(src, srcoff, writeRequestLen);

            sendMessage(Packet.SSH_FXP_WRITE, req.req_id, tw.getBytes());

            pendingStatusQueue.put(req.req_id, req);

            // Only read next status if parallelism reached
            while(pendingStatusQueue.size() >= parallelism) {
                this.readStatus();
            }
            fileOffset += writeRequestLen;
            srcoff += writeRequestLen;
            len -= writeRequestLen;
        }
    }


    /**
     * A read  is divided into multiple requests sent sequentially before
     * reading any status from the server
     */
    private static class OutstandingReadRequest {
        int req_id;
        /**
         * Read offset to request on server starting at the file offset for the first request.
         */
        long serverOffset;
        /**
         * Length of requested data
         */
        int len;
        /**
         * Offset in destination buffer
         */
        int dstOffset;
        /**
         * Temporary buffer
         */
        byte[] buffer;
    }

    /**
     * A read  is divided into multiple requests sent sequentially before
     * reading any status from the server
     */
    private static final class OutstandingStatusRequest {
        int req_id;
    }

}
