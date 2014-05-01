/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.math.BigInteger;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketKexDHReply {

    private final byte[] payload;

    private final byte[] hostKey;
    private final BigInteger f;
    private final byte[] signature;

    public PacketKexDHReply(byte[] hostKey, BigInteger f, byte[] signature) {
        this.hostKey = hostKey;
        this.f = f;
        this.signature = signature;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_KEXDH_REPLY);
        tw.writeString(hostKey, 0, hostKey.length);
        tw.writeMPInt(f);
        tw.writeString(signature, 0, signature.length);
        payload = tw.getBytes();
    }

    public PacketKexDHReply(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_KEXDH_REPLY) {
            throw new PacketTypeException(packet_type);
        }
        hostKey = tr.readByteString();
        f = tr.readMPINT();
        signature = tr.readByteString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }

    public BigInteger getF() {
        return f;
    }

    public byte[] getHostKey() {
        return hostKey;
    }

    public byte[] getSignature() {
        return signature;
    }
}
