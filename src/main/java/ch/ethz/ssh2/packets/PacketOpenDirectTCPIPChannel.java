/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketOpenDirectTCPIPChannel {
    private final byte[] payload;

    public PacketOpenDirectTCPIPChannel(int channelID, int initialWindowSize, int maxPacketSize,
                                        String host_to_connect, int port_to_connect, String originator_IP_address,
                                        int originator_port) {
        TypesWriter tw = new TypesWriter();

        tw.writeByte(Packets.SSH_MSG_CHANNEL_OPEN);
        tw.writeString("direct-tcpip");
        tw.writeUINT32(channelID);
        tw.writeUINT32(initialWindowSize);
        tw.writeUINT32(maxPacketSize);
        tw.writeString(host_to_connect);
        tw.writeUINT32(port_to_connect);
        tw.writeString(originator_IP_address);
        tw.writeUINT32(originator_port);

        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
