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
public final class PacketUserauthInfoRequest {

    private final String name;
    private final String instruction;
    private final String languageTag;
    private final int numPrompts;

    private final String prompt[];
    private final boolean echo[];

    public PacketUserauthInfoRequest(byte payload[]) throws IOException {
        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_USERAUTH_INFO_REQUEST) {
            throw new PacketTypeException(packet_type);
        }
        name = tr.readString();
        instruction = tr.readString();
        languageTag = tr.readString();

        numPrompts = tr.readUINT32();

        prompt = new String[numPrompts];
        echo = new boolean[numPrompts];

        for(int i = 0; i < numPrompts; i++) {
            prompt[i] = tr.readString();
            echo[i] = tr.readBoolean();
        }

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public boolean[] getEcho() {
        return echo;
    }

    public String getInstruction() {
        return instruction;
    }

    public String getLanguageTag() {
        return languageTag;
    }

    public String getName() {
        return name;
    }

    public int getNumPrompts() {
        return numPrompts;
    }

    public String[] getPrompt() {
        return prompt;
    }
}
