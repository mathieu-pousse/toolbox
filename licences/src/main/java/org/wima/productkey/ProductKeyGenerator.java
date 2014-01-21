package org.wima.productkey;

import java.util.*;


/**
 * This class is used to generate / read licence information.
 *
 * @author Mathieu POUSSE <mathieu.pousse@wima.com>
 */
public abstract class ProductKeyGenerator extends ProductKeyManagerImpl {

    /**
     * Pack the information in a licence key.
     *
     * @param values         the values to hide
     * @param sizes          the size of the values
     * @param characterCount the expected licence key size (characters)
     * @param salt           the salt to add
     * @param passes         the number of passes
     * @param showStatistics show some statistics and warning if the key is overloaded
     * @return see description.
     */
    public String pack(final int[] values, final int[] sizes, final int characterCount, final byte[] salt, final int passes, final boolean showStatistics) {

        boolean[] toHide = new boolean[0];

        for (int i = 0; i < values.length; i++) {
            toHide = addAll(toHide, toUnsignedString(values[i], sizes[i]));
        }

        boolean[] salted = new boolean[0];
        for (int i = 0; i < salt.length; i++) {
            salted = addAll(salted, toUnsignedString(salt[i], 8));
        }

        int bitsToHide = 0;
        for (final int size : sizes) {
            bitsToHide += size;
        }

        int bitsToHidePerPass = bitsToHide;
        bitsToHide *= passes;

        if (this.signature == null) {
            // let's generate !
            randomize(bitsToHide, characterCount);
        }
        if (this.signature.length < bitsToHide) {
            throw new IllegalArgumentException("signature length must match the number of bits to hide * passes");
        }
        int bitsPerCharacter = bitsPerCharacters(this.characters);

        boolean[] buffer = new boolean[characterCount * bitsPerCharacter];

        if (showStatistics) {
            int freeSlots = (characterCount * bitsPerCharacter - bitsToHide);
            int ratio = (100 * (buffer.length - freeSlots) / buffer.length);
            System.out.println(ratio + "% of bits holds licence information (" + (buffer.length - freeSlots) + "/" + buffer.length + ")");
            System.out.println(freeSlots + " random bits (2^" + freeSlots + " keys for a licence)");
            if (ratio > 40) {
                System.err.println("be careful, a useful bits ratio > 40% makes the pattern much easier to guess. Ideally, should be around 30%");
            }
        }

        Random random = new Random();
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = random.nextBoolean();
        }

        // hide the message into the buffer respecting the signature
        for (int pass = 0; pass < passes; pass++) {
            for (int i = 0; i < toHide.length; i++) {
                buffer[this.signature[bitsToHidePerPass * pass + i]] = toHide[i];
            }
        }

        // flatten in a string
        StringBuilder encoded = new StringBuilder();
        int saltIndex = 0;
        for (int i = 0; i < buffer.length; i += bitsPerCharacter) {
            int characterIndex = 0;
            for (int j = i; j < i + bitsPerCharacter; j++) {
                characterIndex <<= 1;
                saltIndex = saltIndex % salted.length;
                // add a bit of salt in there !
                if (salted[saltIndex++] ^ buffer[j]) {
                    characterIndex++;
                }
            }
            encoded.append(this.characters[characterIndex]);
        }


        return encoded.toString();
    }

    /**
     * Randomize a new signature.
     *
     * @param secretSize the secret message size (bits)
     * @param keyLength  the licence key length (characters)
     */
    public void randomize(final int secretSize, final int keyLength) {
        int signatureSize = secretSize * PASSES;

        int availableSlots = bitsPerCharacters(this.characters) * keyLength;
        if (signatureSize > availableSlots) {
            // we need more slots to hide the message
            throw new IllegalArgumentException("there are more bits to hide than available bits in the key");
        }
        Random random = new Random();
        this.signature = new int[signatureSize];

        Set<Integer> generated = new HashSet<>();
        while (generated.size() < this.signature.length) {
            generated.add(random.nextInt(availableSlots));
        }
        List<Integer> shuffled = new ArrayList<>(generated);
        Collections.shuffle(shuffled);
        StringBuilder serialized = new StringBuilder();

        int idx = 0;
        for (final Integer integer : shuffled) {
            this.signature[idx++] = integer;
            serialized.append(String.format("%02x", integer));
        }
        System.out.println("signature : " + serialized);
    }

    public static void generate(final ProductKeyGenerator pp, final String message, final String owner, final int[] values, final int[] sizes) {
        byte[] salt = pp.salt(owner);
        System.out.println(message + " <--> " + Arrays.toString(values));
        boolean isFirst = true;
        for (int i = 0; i < 10; i++) {
            String key = pp.pack(values, sizes, KEY_LENGTH, salt, PASSES, isFirst);
            System.out.println(pp.formatKey(key, 5));
            // try to unpack to ensure it is valid
            if (pp.unpack(key, salt, sizes) == null) {
                throw new IllegalArgumentException("unable to unpack values");
            }
            isFirst = false;
        }
    }

    /**
     * Generate some keys...
     *
     * @param args -generate to generate a new signature, otherwise it uses the one from memory
     */
    public static void main(final String... args) {
        ProductKeyGenerator pp = new ProductKeyGenerator() {
            @Override
            public String getLicenceSignature() {
                // change me !
                return "0e3623140a072447203a3b2a042e300c173e280f32191e102b213d3739314a034540152c34082712382226254f060b29";
            }
        };
        int[] sizes = new int[]{4 /* 16 values */, 4 /* 16 values */, 8 /* 256 values */};
        int numberOfBits = /* sumOf(sizes) */ 16;
        if (args.length == 1 && args[0].equals("-generate")) {
            pp.randomize(numberOfBits, KEY_LENGTH);
        } else {
            // as we are not running a CDI, force the initialization
            pp.initialize();
            System.out.println("signature loaded from somewhere out of space");
        }
        // sizes of each item (in bit)

        String owner = "Mathieu POUSSE";
        generate(pp, "enum-1 / 1m /  1", owner, new int[]{1, 1, 1}, sizes);
        generate(pp, "enum-2 / 5m /  5", owner, new int[]{2, 5, 5}, sizes);
        generate(pp, "enum-3 / 1y / 25", owner, new int[]{3, 12, 25}, sizes);
    }

}
