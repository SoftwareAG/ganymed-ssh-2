package ch.ethz.ssh2;

import java.io.IOException;

/**
 * @version $Id$
 */
public class RequestMismatchException extends IOException {

    public RequestMismatchException() {
        super("The server sent an invalid id field.");
    }

    public RequestMismatchException(final String message) {
        super(message);
    }
}
