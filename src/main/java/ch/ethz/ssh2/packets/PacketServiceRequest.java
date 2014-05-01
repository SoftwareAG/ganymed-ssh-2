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
public final class PacketServiceRequest {
    private final byte[] payload;

    private final String serviceName;

    public PacketServiceRequest(String serviceName) {
        this.serviceName = serviceName;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_SERVICE_REQUEST);
        tw.writeString(serviceName);
        payload = tw.getBytes();
    }

    public String getServiceName() {
        return serviceName;
    }

    public PacketServiceRequest(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_SERVICE_REQUEST) {
            throw new PacketTypeException(packet_type);
        }

        serviceName = tr.readString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
