package org.wima.productkey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.util.*;


/**
 * This class is used to generate / read licence information.
 *
 * @author Mathieu POUSSE <mathieu.pousse@wima.com>
 */
public abstract class ProductKeyManagerImpl implements ProductKeyManager {

    /**
     * Available characters in the licence key (64).
     */
    public static final char[] CHARACTERS_64 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '#', '+', '=', '[', ']', '(', ')', '@'};

    /**
     * Available characters in the licence key (32).
     */
    public static final char[] CHARACTERS_32 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9'};


    /**
     * The number of times the information are stored in the licence key.
     */
    public static final int PASSES = 3;

    /**
     * The number character in the licence key (12345-67890-...).
     */
    public static final int KEY_LENGTH = 35;


    private static final Logger LOGGER = LoggerFactory.getLogger(ProductKeyManagerImpl.class);

    protected int[] signature;
    protected char[] characters;

    /**
     * Default constructor.
     */
    public ProductKeyManagerImpl() {
        this(CHARACTERS_32);
    }

    /**
     * This is used when CDI is not available and for test purpose.
     */
    public ProductKeyManagerImpl(final char[] characters) {
        this.characters = characters;
        validate();
    }


    /**
     * Returns the signature from... somewhere...
     *
     * @return see description
     */
    public abstract String getLicenceSignature();

    /**
     * Prepare the service.
     */
    @PostConstruct
    public void initialize() {
        this.loadSignature(getLicenceSignature());
    }

    /**
     * Ensure the character set is well-formed.
     */
    private void validate() {
        int bitPerCharacters = bitsPerCharacters(this.characters);
        if (1 << bitPerCharacters > this.characters.length) {
            throw new IllegalArgumentException("the character set must contains a number of character that is a power of 2 (" + (1 << bitPerCharacters) + " but is only " + this.characters.length + ")");
        }
    }


    /**
     * Calculates the bits per encoded characters.
     *
     * @param characters the character set
     * @return see description
     */
    public int bitsPerCharacters(final char[] characters) {
        int toSplit = Integer.highestOneBit(characters.length - 1);
        int result = 0;
        while (toSplit != 0) {
            result++;
            toSplit >>= 1;
        }
        return result;
    }

    /**
     * Convert the integer to an array of boolean representing the bits.
     */
    protected boolean[] toUnsignedString(final int i, final int length) {
        if (length > 32) {
            throw new IllegalArgumentException("maximum information size is 32 bits");
        }
        boolean[] buffer = new boolean[length];
        int mask = 1;
        int position = length - 1;
        do {
            buffer[position--] = (i & mask) != 0;
            mask <<= 1;
        } while (position >= 0);
        return buffer;
    }

    /**
     * Search for the character position.
     *
     * @param c the character to search.
     * @return the position or -1 if not found
     */
    public int lookup(final char c) {
        for (int i = 0; i < this.characters.length; i++) {
            if (this.characters[i] == c) {
                return i;
            }
        }
        return -1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] salt(final String toHash) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(toHash.getBytes("UTF-8"));
        } catch (Exception e) {
            // ignore...
        }
        return new byte[]{0};
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] unpack(final String key, final byte[] salt, final int[] sizes) {
        int passes = PASSES;
        int bitPerCharacters = bitsPerCharacters(this.characters);
        boolean[] buffer = new boolean[0];
        char[] keyAsChars = normalize(key).toCharArray();
        for (int i = 0; i < keyAsChars.length; i++) {
            int characterIndex = lookup(keyAsChars[i]);
            if (characterIndex == -1) {
                throw new IllegalArgumentException("illegal character");
            }

            buffer = addAll(buffer, toUnsignedString(characterIndex, bitPerCharacters));
        }

        boolean[] salted = new boolean[0];
        for (int i = 0; i < salt.length; i++) {
            salted = addAll(salted, toUnsignedString(salt[i], 8));
        }

        int saltIndex = 0;
        for (int i = 0; i < buffer.length; i++) {
            saltIndex = saltIndex % salted.length;
            buffer[i] = salted[saltIndex++] ^ buffer[i];
        }

        int[][] unpacked = new int[passes][];

        int bitsToGuessPerPass = 0;
        for (int i = 0; i < sizes.length; bitsToGuessPerPass += sizes[i++]) ;

        for (int pass = 0; pass < passes; pass++) {
            int[] result = new int[sizes.length];
            int offset = 0;
            for (int i = 0; i < sizes.length; i++) {
                int value = 0;
                for (int bit = offset; bit < offset + sizes[i]; bit++) {
                    value <<= 1;
                    if (buffer[this.signature[bitsToGuessPerPass * pass + bit]]) {
                        value++;
                    }
                }
                result[i] = value;
                offset += sizes[i];
            }
            unpacked[pass] = result;
        }

        if (unpacked.length == 1) {
            // no redundancy check
        } else {
            for (int i = 0; i < unpacked.length - 1; i++) {
                for (int j = 0; j < unpacked[i].length; j++) {
                    if (unpacked[i][j] != unpacked[i + 1][j]) {
                        // mismatch !
                        LOGGER.error("redundancy check failed");
                        return null;
                    }
                }
            }
        }
        return unpacked[0];
    }

    /**
     * Normalize the licence key by removing separators.
     *
     * @param key the key
     * @return see description.
     */
    private String normalize(final String key) {
        return key.replaceAll("-| ", "");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String formatKey(final String key, final int groupSize) {
        StringBuilder builder = new StringBuilder();
        String normalized = normalize(key);
        for (int i = 0; i < normalized.length(); i += groupSize) {
            builder.append(normalized.substring(i, Math.min(i + groupSize, normalized.length())));
            if (i + groupSize < normalized.length()) {
                builder.append("-");
            }
        }
        return builder.toString();
    }

    /**
     * Loads the specified signature.
     *
     * @param serialized the serialized signature
     */
    protected void loadSignature(final String serialized) {
        if (serialized.length() % 2 != 0) {
            throw new IllegalArgumentException("signature length does not match");
        }
        this.signature = new int[serialized.length() / 2];

        for (int i = 0; i < serialized.length(); i += 2) {
            this.signature[i / 2] = Integer.parseInt(serialized.substring(i, i + 2), 16);
        }
    }


    /* - this is copied from Apache commons -------------------------------------------------- */

    protected boolean[] addAll(boolean[] array1, boolean[] array2) {
        if (array1 == null) {
            return array2;
        } else if (array2 == null) {
            return array1;
        }
        boolean[] joinedArray = (boolean[]) Array.newInstance(array1.getClass().getComponentType(),
                array1.length + array2.length);
        System.arraycopy(array1, 0, joinedArray, 0, array1.length);
        System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
        return joinedArray;
    }

    public static void main(String... args) {
        ProductKeyManager pp = new ProductKeyManagerImpl() {
            @Override
            public String getLicenceSignature() {
                return "0e3623140a072447203a3b2a042e300c173e280f32191e102b213d3739314a034540152c34082712382226254f060b29";
            }
        };
        // as we are not running a CDI, force the initialization
        ((ProductKeyManagerImpl) pp).initialize();
        String owner = "Mathieu POUSSE";
        System.out.println(Arrays.toString(pp.unpack("IXDIE-AXA4W-K8GG6-UU3R1-KMF99-3R6RB-Y6GRC", pp.salt(owner), new int[]{4, 4, 8})));
    }

}
