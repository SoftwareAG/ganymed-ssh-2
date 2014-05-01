package ch.ethz.ssh2.transport;

import java.io.IOException;

/**
 * @version $Id:$
 */
public class DisconnectException extends IOException {

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

    private Reason reason;

    public DisconnectException(final Reason reason, final String message) {
        super(message);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
