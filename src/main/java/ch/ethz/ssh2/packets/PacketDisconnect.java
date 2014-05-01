/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketDisconnect {

    public enum Reason {
        SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,
        SSH_DISCONNECT_PROTOCOL_ERROR,
        SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
        SSH_DISCONNECT_RESERVED,
        SSH_DISCONNECT_MAC_ERROR,
        SSH_DISCONNECT_COMPRESSION_ERROR,
        SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
        SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
        SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
        SSH_DISCONNECT_CONNECTION_LOST,
        SSH_DISCONNECT_BY_APPLICATION,
        SSH_DISCONNECT_TOO_MANY_CONNECTIONS,
        SSH_DISCONNECT_AUTH_CANCELLED_BY_USER,
        SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
        SSH_DISCONNECT_ILLEGAL_USER_NAME
    }

    private final byte[] payload;

    private final Reason reason;

    private final String message;

    public PacketDisconnect(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_DISCONNECT) {
            throw new PacketTypeException(packet_type);
        }
        reason = PacketDisconnect.Reason.values()[tr.readUINT32()];
        message = tr.readString();
        String lang = tr.readString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public PacketDisconnect(Reason reason, String desc) {
        this.reason = reason;
        this.message = desc;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_DISCONNECT);
        tw.writeUINT32(reason.ordinal());
        tw.writeString(desc);
        tw.writeString("");
        payload = tw.getBytes();
    }

    public Reason getReason() {
        return reason;
    }

    public String getMessage() {
        return message;
    }

    public byte[] getPayload() {
        return payload;
    }
}
