package ar.emily.chat.stuff;

import javax.crypto.SecretKey;

public record Keys(
    SecretKey localKey, byte[] localIv,
    SecretKey remoteKey, byte[] remoteIv
) {
}
