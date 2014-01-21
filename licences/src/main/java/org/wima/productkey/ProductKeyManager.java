package org.wima.productkey;

/**
 * Read a symmetrically encoded key.
 *
 * @author Mathieu POUSSE <mathieu.pousse@wima.com>
 */
public interface ProductKeyManager {

    byte[] salt(String toHash);

    /**
     * Unpack the information from the key
     *
     * @param key   the key
     * @param salt  the salt to add
     * @param sizes the size of expected data
     * @return see description
     */
    int[] unpack(String key, byte[] salt, int[] sizes);

    /**
     * Return a formatted version of the key.
     *
     * @param key        the key to format
     * @param packetSize the packet size
     * @return see description
     */
    String formatKey(String key, int packetSize);

}
