/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketServiceAccept {
    private final byte[] payload;

    public PacketServiceAccept(String serviceName) {

        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_SERVICE_ACCEPT);
        tw.writeString(serviceName);
        payload = tw.getBytes();
    }

    public PacketServiceAccept(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_SERVICE_ACCEPT) {
            throw new PacketTypeException(packet_type);
        }
        if(tr.remain() != 0) {
            String serviceName = tr.readString();
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
