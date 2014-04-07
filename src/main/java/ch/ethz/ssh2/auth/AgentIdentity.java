/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.auth;

public interface AgentIdentity {
    String getAlgName();
    byte[] getPublicKeyBlob();
    byte[] sign(byte[] data);
}
