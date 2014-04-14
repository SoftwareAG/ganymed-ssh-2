package ch.ethz.ssh2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.sftp.AceMask;
import ch.ethz.ssh2.sftp.ErrorCodes;
import ch.ethz.ssh2.sftp.OpenFlags;
import ch.ethz.ssh2.sftp.Packet;

/**
 * @version $Id$
 */
public class SFTPv6Client extends AbstractSFTPClient {
    private static final Logger log = Logger.getLogger(SFTPv6Client.class);

    private PacketListener listener;

    public SFTPv6Client(Connection conn) throws IOException {
        this(conn, new PacketListener() {
            public void read(String packet) {
                log.debug("Read packet " + packet);
            }

            public void write(String packet) {
                log.debug("Write packet " + packet);
            }
        });
    }

    public SFTPv6Client(Connection conn, PacketListener listener) throws IOException {
        super(conn, 6, listener);
        this.listener = listener;
    }

    @Override
    public SFTPv6FileAttributes fstat(SFTPFileHandle handle) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(handle.getHandle(), 0, handle.getHandle().length);

        sendMessage(Packet.SSH_FXP_FSTAT, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_ATTRS) {
            return new SFTPv6FileAttributes(tr);
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    private SFTPv6FileAttributes statBoth(String path, int statMethod) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(path, this.getCharset());

        sendMessage(statMethod, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_ATTRS) {
            return new SFTPv6FileAttributes(tr);
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
    public SFTPv6FileAttributes stat(String path) throws IOException {
        return statBoth(path, Packet.SSH_FXP_STAT);
    }

    @Override
    public SFTPv6FileAttributes lstat(String path) throws IOException {
        return statBoth(path, Packet.SSH_FXP_LSTAT);
    }


    private List<SFTPv6DirectoryEntry> scanDirectory(byte[] handle) throws IOException {
        List<SFTPv6DirectoryEntry> files = new ArrayList<SFTPv6DirectoryEntry>();

        while(true) {
            int req_id = generateNextRequestID();

            TypesWriter tw = new TypesWriter();
            tw.writeString(handle, 0, handle.length);

            sendMessage(Packet.SSH_FXP_READDIR, req_id, tw.getBytes());

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
                if(log.isDebugEnabled()) {
                    log.debug(String.format("Parsing %d name entries", count));
                }
                while(count > 0) {
                    SFTPv6DirectoryEntry file = new SFTPv6DirectoryEntry();
                    file.filename = tr.readString(this.getCharset());
                    listener.read(file.filename);
                    file.attributes = new SFTPv6FileAttributes(tr);
                    if(log.isDebugEnabled()) {
                        log.debug(String.format("Adding file %s", file));
                    }
                    files.add(file);
                    count--;
                }
                continue;
            }
            if(t != Packet.SSH_FXP_STATUS) {
                throw new PacketTypeException(t);
            }
            int errorCode = tr.readUINT32();
            if(errorCode == ErrorCodes.SSH_FX_EOF) {
                return files;
            }
            String errorMessage = tr.readString();
            listener.read(errorMessage);
            throw new SFTPException(errorMessage, errorCode);
        }
    }

    @Override
    public final SFTPFileHandle openDirectory(String path) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(path, this.getCharset());

        sendMessage(Packet.SSH_FXP_OPENDIR, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_HANDLE) {
            return new SFTPFileHandle(this, tr.readByteString());
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    /**
     * List the contents of a directory.
     *
     * @param dirName See the {@link SFTPv6Client comment} for the class for more details.
     * @return A Vector containing {@link SFTPv6DirectoryEntry} objects.
     * @throws IOException
     */
    @Override
    public List<SFTPv6DirectoryEntry> ls(String dirName) throws IOException {
        SFTPFileHandle handle = openDirectory(dirName);
        List<SFTPv6DirectoryEntry> result = scanDirectory(handle.getHandle());
        closeFile(handle);
        return result;
    }

    /**
     * Create a file and open it for reading and writing.
     * Same as {@link #createFile(String, SFTPFileAttributes) createFile(fileName, null)}.
     *
     * @param filename See the {@link SFTPv6Client comment} for the class for more details.
     * @return a SFTPFileHandle handle
     * @throws IOException
     */
    @Override
    public SFTPFileHandle createFile(String filename) throws IOException {
        return createFile(filename, new SFTPv6FileAttributes());
    }

    /**
     * Create a file and open it for reading and writing.
     * You can specify the default attributes of the file (the server may or may
     * not respect your wishes).
     *
     * @param filename See the {@link SFTPv6Client comment} for the class for more details.
     * @param attr     may be <code>null</code> to use server defaults. Probably only
     *                 the <code>uid</code>, <code>gid</code> and <code>permissions</code>
     *                 (remember the server may apply a umask) entries of the {@link SFTPFileHandle}
     *                 structure make sense. You need only to set those fields where you want
     *                 to override the server's defaults.
     * @return a SFTPFileHandle handle
     * @throws IOException
     */
    @Override
    public SFTPFileHandle createFile(String filename, SFTPFileAttributes attr) throws IOException {
        return openFile(filename, OpenFlags.SSH_FXF_CREATE_NEW, attr);
    }

    @Override
    public SFTPFileHandle openFile(String filename, int flags) throws IOException {
        return this.openFile(filename, flags, new SFTPv6FileAttributes());
    }

    @Override
    public SFTPFileHandle openFile(String filename, int flags, SFTPFileAttributes attr) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(filename, this.getCharset());
        tw.writeUINT32(AceMask.ACE4_READ_DATA | AceMask.ACE4_READ_ATTRIBUTES | AceMask.ACE4_READ_ACL | AceMask.ACE4_READ_NAMED_ATTRS
                | AceMask.ACE4_WRITE_DATA | AceMask.ACE4_APPEND_DATA | AceMask.ACE4_WRITE_ATTRIBUTES | AceMask.ACE4_WRITE_ACL | AceMask.ACE4_WRITE_NAMED_ATTRS);
        tw.writeUINT32(flags);

        tw.writeBytes(attr.toBytes());

        sendMessage(Packet.SSH_FXP_OPEN, req_id, tw.getBytes());

        byte[] resp = receiveMessage(34000);

        TypesReader tr = new TypesReader(resp);

        int t = tr.readByte();
        listener.read(Packet.forName(t));

        int rep_id = tr.readUINT32();
        if(rep_id != req_id) {
            throw new RequestMismatchException();
        }

        if(t == Packet.SSH_FXP_HANDLE) {
            return new SFTPFileHandle(this, tr.readByteString());
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
    public void createSymlink(String src, String target) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        // new-link-path
        tw.writeString(src, this.getCharset());
        // existing-path
        tw.writeString(target, this.getCharset());
        tw.writeBoolean(true);

        sendMessage(Packet.SSH_FXP_LINK, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }

    @Override
    public void createHardlink(String src, String target) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        // new-link-path
        tw.writeString(src, this.getCharset());
        // existing-path
        tw.writeString(target, this.getCharset());
        tw.writeBoolean(false);

        sendMessage(Packet.SSH_FXP_LINK, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }
}
