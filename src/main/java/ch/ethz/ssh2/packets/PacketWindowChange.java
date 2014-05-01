package ch.ethz.ssh2.packets;

/**
 * Indicates that that size of the terminal (window) size has changed on the client side.
 * <p/>
 * See section 6.7 of RFC 4254.
 *
 * @author Kohsuke Kawaguchi
 */
public final class PacketWindowChange {
    private final byte[] payload;

    public PacketWindowChange(int recipientChannelID,
                              int character_width, int character_height, int pixel_width, int pixel_height) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
        tw.writeUINT32(recipientChannelID);
        tw.writeString("window-change");
        tw.writeBoolean(false);
        tw.writeUINT32(character_width);
        tw.writeUINT32(character_height);
        tw.writeUINT32(pixel_width);
        tw.writeUINT32(pixel_height);

        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
