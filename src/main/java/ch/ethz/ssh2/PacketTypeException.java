package ch.ethz.ssh2;

import java.io.IOException;

/**
 * @version $Id$
 */
public class PacketTypeException extends IOException {

    public PacketTypeException() {
    }

    public PacketTypeException(final String message) {
        super(message);
    }

    public PacketTypeException(final int packet) {
        super(String.format("The SFTP server sent an unexpected packet type (%d)", packet));
    }

    public PacketTypeException(final int packet, final String message) {
        super(String.format("The SFTP server sent an invalid packet type (%d). %s", packet, message));
    }
}
