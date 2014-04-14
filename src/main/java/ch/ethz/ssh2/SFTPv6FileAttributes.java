/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2;

import java.io.IOException;

import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.sftp.AttribFlags;
import ch.ethz.ssh2.sftp.AttribTypes;

/**
 * A <code>SFTPv3FileAttributes</code> object represents detail information
 * about a file on the server. Not all fields may/must be present.
 *
 * @author Christian Plattner, plattner@inf.ethz.ch
 * @version $Id$
 */

public class SFTPv6FileAttributes implements SFTPFileAttributes {

    /**
     * The type field is always present
     *
     * @see ch.ethz.ssh2.sftp.AttribTypes
     */
    private Integer type = null;

    /**
     * The SIZE attribute. <code>NULL</code> if not present.
     */
    public Long size = null;

    /**
     * The POSIX permissions. <code>NULL</code> if not present.
     * <p/>
     * Here is a list:
     * <p/>
     * <pre>Note: these numbers are all OCTAL.
     * <p/>
     *  S_IFMT     0170000   bitmask for the file type bitfields
     *  S_IFSOCK   0140000   socket
     *  S_IFLNK    0120000   symbolic link
     *  S_IFREG    0100000   regular file
     *  S_IFBLK    0060000   block device
     *  S_IFDIR    0040000   directory
     *  S_IFCHR    0020000   character device
     *  S_IFIFO    0010000   fifo
     *  S_ISUID    0004000   set UID bit
     *  S_ISGID    0002000   set GID bit
     *  S_ISVTX    0001000   sticky bit
     * <p/>
     *  S_IRWXU    00700     mask for file owner permissions
     *  S_IRUSR    00400     owner has read permission
     *  S_IWUSR    00200     owner has write permission
     *  S_IXUSR    00100     owner has execute permission
     *  S_IRWXG    00070     mask for group permissions
     *  S_IRGRP    00040     group has read permission
     *  S_IWGRP    00020     group has write permission
     *  S_IXGRP    00010     group has execute permission
     *  S_IRWXO    00007     mask for permissions for others (not in group)
     *  S_IROTH    00004     others have read permission
     *  S_IWOTH    00002     others have write permisson
     *  S_IXOTH    00001     others have execute permission
     * </pre>
     */
    public Integer permissions = null;

    /**
     * Creation time of the file.
     * <p/>
     * The createtime attribute. Represented as seconds from Jan 1, 1970 in UTC.
     * <code>NULL</code> if not present.
     */
    public Long createtime = null;

    /**
     * Last access time of the file.
     * <p/>
     * The atime attribute. Represented as seconds from Jan 1, 1970 in UTC.
     * <code>NULL</code> if not present.
     */
    public Long atime = null;

    /**
     * The mtime attribute. Represented as seconds from Jan 1, 1970 in UTC.
     * <code>NULL</code> if not present.
     */
    public Long mtime = null;

    /**
     * Last time the file attributes were changed.  The exact meaning of this field depends on the server.
     * <p/>
     * The ctime attribute. Represented as seconds from Jan 1, 1970 in UTC.
     * <code>NULL</code> if not present.
     */
    public Long ctime = null;

    /**
     * The 'owner' and 'group' fields are represented as UTF-8 strings. user@localhost represents
     * a user in the context of the server.
     */
    public String owner = null;

    /**
     * The 'owner' and 'group' fields are represented as UTF-8 strings
     */
    public String group = null;

    /**
     * Checks if this entry is a directory.
     *
     * @return Returns true if permissions are available and they indicate
     * that this entry represents a directory.
     */
    @Override
    public boolean isDirectory() {
        return (type & AttribTypes.SSH_FILEXFER_TYPE_DIRECTORY) == AttribTypes.SSH_FILEXFER_TYPE_DIRECTORY;
    }

    /**
     * Checks if this entry is a regular file.
     *
     * @return Returns true if permissions are available and they indicate
     * that this entry represents a regular file.
     */
    @Override
    public boolean isRegularFile() {
        return (type & AttribTypes.SSH_FILEXFER_TYPE_REGULAR) == AttribTypes.SSH_FILEXFER_TYPE_REGULAR;
    }

    /**
     * Checks if this entry is a a symlink.
     *
     * @return Returns true if permissions are available and they indicate
     * that this entry represents a symlink.
     */
    @Override
    public boolean isSymlink() {
        return (type & AttribTypes.SSH_FILEXFER_TYPE_SYMLINK) == AttribTypes.SSH_FILEXFER_TYPE_SYMLINK;
    }

    public SFTPv6FileAttributes() {
        //
    }

    /**
     * uint32   valid-attribute-flags
     * byte     type                   always present
     * uint64   size                   if flag SIZE
     * uint64   allocation-size        if flag ALLOCATION_SIZE
     * string   owner                  if flag OWNERGROUP
     * string   group                  if flag OWNERGROUP
     * uint32   permissions            if flag PERMISSIONS
     * int64    atime                  if flag ACCESSTIME
     * uint32   atime-nseconds            if flag SUBSECOND_TIMES
     * int64    createtime             if flag CREATETIME
     * uint32   createtime-nseconds       if flag SUBSECOND_TIMES
     * int64    mtime                  if flag MODIFYTIME
     * uint32   mtime-nseconds            if flag SUBSECOND_TIMES
     * int64    ctime                  if flag CTIME
     * uint32   ctime-nseconds            if flag SUBSECOND_TIMES
     * string   acl                    if flag ACL
     * uint32   attrib-bits            if flag BITS
     * uint32   attrib-bits-valid      if flag BITS
     * byte     text-hint              if flag TEXT_HINT
     * string   mime-type              if flag MIME_TYPE
     * uint32   link-count             if flag LINK_COUNT
     * string   untranslated-name      if flag UNTRANSLATED_NAME
     * uint32   extended-count         if flag EXTENDED
     * extension-pair extensions
     */
    public SFTPv6FileAttributes(final TypesReader tr) throws IOException {
        int flags = tr.readUINT32();
        // The type field is always present
        this.type = tr.readByte();
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_SIZE) != 0) {
            this.size = tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0) {
            // Ignore
            tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            this.owner = tr.readString();
            this.group = tr.readString();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            this.permissions = tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
            this.atime = tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            // Ignore
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
            this.createtime = tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            // Ignore
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
            this.mtime = tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            // Ignore
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_CTIME) != 0) {
            this.ctime = tr.readUINT64();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            // Ignore
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_ACL) != 0) {
            // Ignore
            tr.readString();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_BITS) != 0) {
            // Ignore attrib-bits
            tr.readUINT32();
            // Ignore attrib-bits-valid
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_TEXT_HINT) != 0) {
            // Ignore
            tr.readByte();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_MIME_TYPE) != 0) {
            // Ignore
            tr.readString();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_LINK_COUNT) != 0) {
            // Ignore
            tr.readUINT32();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) != 0) {
            // Ignore
            tr.readString();
        }
        if((flags & AttribFlags.SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            int count = tr.readUINT32();
            // Read it anyway to detect corrupt packets
            while(count > 0) {
                // extension-name
                tr.readByteString();
                // extension-data
                tr.readByteString();
                count--;
            }
        }
    }

    /**
     * The same encoding is used both when returning file
     * attributes from the server and when sending file attributes to the
     * server.
     *
     * @return Encoded attributes
     */
    @Override
    public byte[] toBytes() {
        TypesWriter tw = new TypesWriter();
        // The 'valid-attribute-flags' specifies which of the fields are present.  Those fields
        // for which the corresponding flag is not set are not present
        int attrFlags = 0;
        if(this.size != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_SIZE;
        }
        if((this.owner != null) && (this.group != null)) {
            // If either the owner or group field is zero length, the field should
            // be considered absent, and no change should be made to that specific
            // field during a modification operation.
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_OWNERGROUP;
        }
        if(this.permissions != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if(this.atime != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_ACCESSTIME;
        }
        if(this.createtime != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_CREATETIME;
        }
        if(this.mtime != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_MODIFYTIME;
        }
        if(this.ctime != null) {
            attrFlags = attrFlags | AttribFlags.SSH_FILEXFER_ATTR_CTIME;
        }
        tw.writeUINT32(attrFlags);
        // The type field is always present.
        if(this.size != null) {
            tw.writeUINT64(this.size);
        }
        if((this.owner != null) && (this.group != null)) {
            tw.writeString(owner);
            tw.writeString(group);
        }
        if(this.permissions != null) {
            tw.writeUINT32(this.permissions);
        }
        if(this.atime != null) {
            tw.writeUINT64(this.atime);
        }
        if(this.createtime != null) {
            tw.writeUINT64(this.createtime);
        }
        if(this.mtime != null) {
            tw.writeUINT64(this.mtime);
        }
        if(this.ctime != null) {
            tw.writeUINT64(this.ctime);
        }
        return tw.getBytes();
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("SFTPv6FileAttributes{");
        sb.append("type=").append(type);
        sb.append(", size=").append(size);
        sb.append(", permissions=").append(permissions);
        sb.append(", createtime=").append(createtime);
        sb.append(", atime=").append(atime);
        sb.append(", mtime=").append(mtime);
        sb.append(", ctime=").append(ctime);
        sb.append(", owner='").append(owner).append('\'');
        sb.append(", group='").append(group).append('\'');
        sb.append('}');
        return sb.toString();
    }
}