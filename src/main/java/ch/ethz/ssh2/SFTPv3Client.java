/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.sftp.ErrorCodes;
import ch.ethz.ssh2.sftp.Packet;

/**
 * A <code>SFTPv3Client</code> represents a SFTP (protocol version 3)
 * client connection tunnelled over a SSH-2 connection. This is a very simple
 * (synchronous) implementation.
 * <p/>
 * Basically, most methods in this class map directly to one of
 * the packet types described in draft-ietf-secsh-filexfer-02.txt.
 * <p/>
 * Note: this is experimental code.
 * <p/>
 * Error handling: the methods of this class throw IOExceptions. However, unless
 * there is catastrophic failure, exceptions of the type {@link SFTPv3Client} will
 * be thrown (a subclass of IOException). Therefore, you can implement more verbose
 * behavior by checking if a thrown exception if of this type. If yes, then you
 * can cast the exception and access detailed information about the failure.
 * <p/>
 * Notes about file names, directory names and paths, copy-pasted
 * from the specs:
 * <ul>
 * <li>SFTP v3 represents file names as strings. File names are
 * assumed to use the slash ('/') character as a directory separator.</li>
 * <li>File names starting with a slash are "absolute", and are relative to
 * the root of the file system.  Names starting with any other character
 * are relative to the user's default directory (home directory).</li>
 * <li>Servers SHOULD interpret a path name component ".." as referring to
 * the parent directory, and "." as referring to the current directory.
 * If the server implementation limits access to certain parts of the
 * file system, it must be extra careful in parsing file names when
 * enforcing such restrictions.  There have been numerous reported
 * security bugs where a ".." in a path name has allowed access outside
 * the intended area.</li>
 * <li>An empty path name is valid, and it refers to the user's default
 * directory (usually the user's home directory).</li>
 * </ul>
 * <p/>
 * If you are still not tired then please go on and read the comment for
 * {@link #setCharset(String)}.
 *
 * @author Christian Plattner, plattner@inf.ethz.ch
 * @version $Id$
 */
public class SFTPv3Client extends AbstractSFTPClient {
    private static final Logger log = Logger.getLogger(SFTPv3Client.class);

    /**
     * Open the file for reading.
     */
    public static final int SSH_FXF_READ = 0x00000001;
    /**
     * Open the file for writing.  If both this and SSH_FXF_READ are
     * specified, the file is opened for both reading and writing.
     */
    public static final int SSH_FXF_WRITE = 0x00000002;
    /**
     * Force all writes to append data at the end of the file.
     */
    public static final int SSH_FXF_APPEND = 0x00000004;
    /**
     * If this flag is specified, then a new file will be created if one
     * does not alread exist (if O_TRUNC is specified, the new file will
     * be truncated to zero length if it previously exists).
     */
    public static final int SSH_FXF_CREAT = 0x00000008;
    /**
     * Forces an existing file with the same name to be truncated to zero
     * length when creating a file by specifying SSH_FXF_CREAT.
     * SSH_FXF_CREAT MUST also be specified if this flag is used.
     */
    public static final int SSH_FXF_TRUNC = 0x00000010;
    /**
     * Causes the request to fail if the named file already exists.
     */
    public static final int SSH_FXF_EXCL = 0x00000020;

    private PacketListener listener;

    /**
     * Create a SFTP v3 client.
     *
     * @param conn The underlying SSH-2 connection to be used.
     * @throws IOException
     */
    public SFTPv3Client(Connection conn) throws IOException {
        this(conn, new PacketListener() {
            public void read(String packet) {
                log.debug("Read packet " + packet);
            }

            public void write(String packet) {
                log.debug("Write packet " + packet);
            }
        });
    }

    /**
     * Create a SFTP v3 client.
     *
     * @param conn The underlying SSH-2 connection to be used.
     * @throws IOException
     */
    public SFTPv3Client(Connection conn, PacketListener listener) throws IOException {
        super(conn, 3, listener);
        this.listener = listener;
    }

    @Override
    public SFTPv3FileAttributes fstat(SFTPFileHandle handle) throws IOException {
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
            return new SFTPv3FileAttributes(tr);
        }

        if(t != Packet.SSH_FXP_STATUS) {
            throw new PacketTypeException(t);
        }

        int errorCode = tr.readUINT32();
        String errorMessage = tr.readString();
        listener.read(errorMessage);
        throw new SFTPException(errorMessage, errorCode);
    }

    private SFTPv3FileAttributes statBoth(String path, int statMethod) throws IOException {
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
            return new SFTPv3FileAttributes(tr);
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
    public SFTPv3FileAttributes stat(String path) throws IOException {
        return statBoth(path, Packet.SSH_FXP_STAT);
    }

    @Override
    public SFTPv3FileAttributes lstat(String path) throws IOException {
        return statBoth(path, Packet.SSH_FXP_LSTAT);
    }


    private List<SFTPv3DirectoryEntry> scanDirectory(byte[] handle) throws IOException {
        List<SFTPv3DirectoryEntry> files = new ArrayList<SFTPv3DirectoryEntry>();

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
                    SFTPv3DirectoryEntry file = new SFTPv3DirectoryEntry();
                    file.filename = tr.readString(this.getCharset());
                    file.longEntry = tr.readString(this.getCharset());
                    listener.read(file.longEntry);
                    file.attributes = new SFTPv3FileAttributes(tr);
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
    public final SFTPv3FileHandle openDirectory(String path) throws IOException {
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
            return new SFTPv3FileHandle(this, tr.readByteString());
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
     * @param dirName See the {@link SFTPv3Client comment} for the class for more details.
     * @return A Vector containing {@link SFTPv3DirectoryEntry} objects.
     * @throws IOException
     */
    @Override
    public List<SFTPv3DirectoryEntry> ls(String dirName) throws IOException {
        SFTPv3FileHandle handle = openDirectory(dirName);
        List<SFTPv3DirectoryEntry> result = scanDirectory(handle.getHandle());
        closeFile(handle);
        return result;
    }

    /**
     * Open a file for reading.
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle openFileRO(String filename) throws IOException {
        return openFile(filename, SSH_FXF_READ, new SFTPv3FileAttributes());
    }

    /**
     * Open a file for reading and writing.
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle openFileRW(String filename) throws IOException {
        return openFile(filename, SSH_FXF_READ | SSH_FXF_WRITE, new SFTPv3FileAttributes());
    }

    /**
     * Open a file in append mode. The SFTP v3 draft says nothing but assuming normal POSIX
     * behavior, all writes will be appendend to the end of the file, no matter which offset
     * one specifies.
     * <p/>
     * A side note for the curious: OpenSSH does an lseek() to the specified writing offset before each write(),
     * even for writes to files opened in O_APPEND mode. However, bear in mind that when working
     * in the O_APPEND mode, each write() includes an implicit lseek() to the end of the file
     * (well, this is what the newsgroups say).
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle openFileRWAppend(String filename) throws IOException {
        return openFile(filename, SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND, new SFTPv3FileAttributes());
    }

    /**
     * Open a file in append mode. The SFTP v3 draft says nothing but assuming normal POSIX
     * behavior, all writes will be appendend to the end of the file, no matter which offset
     * one specifies.
     * <p/>
     * A side note for the curious: OpenSSH does an lseek() to the specified writing offset before each write(),
     * even for writes to files opened in O_APPEND mode. However, bear in mind that when working
     * in the O_APPEND mode, each write() includes an implicit lseek() to the end of the file
     * (well, this is what the newsgroups say).
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle openFileWAppend(String filename) throws IOException {
        return openFile(filename, SSH_FXF_WRITE | SSH_FXF_APPEND, new SFTPv3FileAttributes());
    }

    @Override
    public SFTPv3FileHandle createFile(String filename) throws IOException {
        return createFile(filename, new SFTPv3FileAttributes());
    }

    @Override
    public SFTPv3FileHandle createFile(String filename, SFTPFileAttributes attr) throws IOException {
        return openFile(filename, SSH_FXF_CREAT | SSH_FXF_READ | SSH_FXF_WRITE, attr);
    }

    /**
     * Create a file (truncate it if it already exists) and open it for writing.
     * Same as {@link #createFileTruncate(String, SFTPFileAttributes) createFileTruncate(filename, null)}.
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle createFileTruncate(String filename) throws IOException {
        return createFileTruncate(filename, new SFTPv3FileAttributes());
    }

    /**
     * reate a file (truncate it if it already exists) and open it for writing.
     * You can specify the default attributes of the file (the server may or may
     * not respect your wishes).
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @param attr     may be <code>null</code> to use server defaults. Probably only
     *                 the <code>uid</code>, <code>gid</code> and <code>permissions</code>
     *                 (remember the server may apply a umask) entries of the {@link SFTPv3FileHandle}
     *                 structure make sense. You need only to set those fields where you want
     *                 to override the server's defaults.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    public SFTPv3FileHandle createFileTruncate(String filename, SFTPFileAttributes attr) throws IOException {
        return openFile(filename, SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_WRITE, attr);
    }

    @Override
    public SFTPv3FileHandle openFile(String filename, int flags) throws IOException {
        return openFile(filename, flags, new SFTPv3FileAttributes());
    }

    @Override
    public SFTPv3FileHandle openFile(String filename, int flags, SFTPFileAttributes attr) throws IOException {
        int req_id = generateNextRequestID();

        TypesWriter tw = new TypesWriter();
        tw.writeString(filename, this.getCharset());
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
            return new SFTPv3FileHandle(this, tr.readByteString());
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

        // Changed semantics of src and target. The bug is known on SFTP servers shipped with all
        // versions of OpenSSH (Bug #861).
        TypesWriter tw = new TypesWriter();
        tw.writeString(target, this.getCharset());
        tw.writeString(src, this.getCharset());

        sendMessage(Packet.SSH_FXP_SYMLINK, req_id, tw.getBytes());

        expectStatusOKMessage(req_id);
    }
}
