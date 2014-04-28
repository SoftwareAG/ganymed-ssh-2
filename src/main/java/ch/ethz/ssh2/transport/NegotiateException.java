/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.transport;

import java.io.IOException;

/**
 * @version $Id$
 */
public class NegotiateException extends IOException {
    private static final long serialVersionUID = 3689910669428143157L;

    public NegotiateException() {
        //
    }

    public NegotiateException(String message) {
        super(message);
    }
}
