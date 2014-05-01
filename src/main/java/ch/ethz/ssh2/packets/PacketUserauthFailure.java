/*
 * Copyright (c) 2006-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketUserauthFailure {

    private final byte[] payload;

    private Set<String> authThatCanContinue;

    private boolean partialSuccess;

    public PacketUserauthFailure(Set<String> authThatCanContinue, boolean partialSuccess) {
        this.authThatCanContinue = authThatCanContinue;
        this.partialSuccess = partialSuccess;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_FAILURE);
        tw.writeNameList(authThatCanContinue.toArray(new String[authThatCanContinue.size()]));
        tw.writeBoolean(partialSuccess);
        payload = tw.getBytes();
    }

    public PacketUserauthFailure(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_USERAUTH_FAILURE) {
            throw new PacketTypeException(packet_type);
        }
        authThatCanContinue = new HashSet<String>(Arrays.asList(tr.readNameList()));
        partialSuccess = tr.readBoolean();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }

    public Set<String> getAuthThatCanContinue() {
        return authThatCanContinue;
    }

    public boolean isPartialSuccess() {
        return partialSuccess;
    }
}
