#include <opus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void Require(int value, const char* message) {
    if (!value) { fprintf(stderr, "%s\n", message); exit(1); }
}

static FILE* Output(const char* directory, const char* name) {
    char path[32768];
    Require(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0, "output path failed");
    FILE* stream = fopen(path, "wb");
    Require(stream != NULL, "open reference output failed");
    return stream;
}

static void Generate(const char* directory, int channels) {
    int error = 0;
    OpusEncoder* encoder = opus_encoder_create(48000, channels, OPUS_APPLICATION_RESTRICTED_LOWDELAY, &error);
    Require(encoder != NULL && error == OPUS_OK, "official encoder creation failed");
    OpusDecoder* decoder = opus_decoder_create(48000, channels, &error);
    Require(decoder != NULL && error == OPUS_OK, "official decoder creation failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_BITRATE(channels * 48000)) == OPUS_OK, "set bitrate failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_VBR(0)) == OPUS_OK, "set CBR failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(10)) == OPUS_OK, "set complexity failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC)) == OPUS_OK, "set music signal failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND)) == OPUS_OK, "set bandwidth failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_DTX(0)) == OPUS_OK, "disable DTX failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_INBAND_FEC(0)) == OPUS_OK, "disable FEC failed");
    Require(opus_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(0)) == OPUS_OK, "disable loss input failed");
    FILE* packets = Output(directory, channels == 1 ? "celt-mono-packets.bin" : "celt-stereo-packets.bin");
    FILE* reference = Output(directory, channels == 1 ? "celt-mono-reference-s16le.pcm" : "celt-stereo-reference-s16le.pcm");
    FILE* original = Output(directory, channels == 1 ? "celt-mono-input-s16le.pcm" : "celt-stereo-input-s16le.pcm");
    for (int frame = 0; frame < 8; ++frame) {
        int16_t input[1920];
        int16_t output[1920];
        uint8_t packet[4000];
        for (int sample = 0; sample < 960; ++sample) {
            const int index = frame * 960 + sample;
            const int left = index % 160;
            const int right = (index + 19) % 80;
            input[sample * channels] = (int16_t)(left < 80 ? left * 25 - 1000 : 3000 - left * 25);
            if (channels == 2)
                input[sample * 2 + 1] = (int16_t)(right < 40 ? right * 30 - 600 : 1800 - right * 30);
        }
        const int bytes = opus_encode(encoder, input, 960, packet, sizeof(packet));
        Require(bytes > 0 && (packet[0] >> 3) >= 16 && (packet[0] >> 3) <= 31, "encoder did not produce CELT-only Opus packet");
        const int samples = opus_decode(decoder, packet, bytes, output, 960, 0);
        Require(samples == 960, "official decoder returned wrong duration");
        int peak = 0;
        for (int sample = 0; sample < samples * channels; ++sample) {
            const int magnitude = abs(output[sample]);
            if (magnitude > peak) peak = magnitude;
        }
        Require(peak > 100, "official reference is silent");
        const uint8_t length[4] = {(uint8_t)bytes, (uint8_t)(bytes >> 8), (uint8_t)(bytes >> 16), (uint8_t)(bytes >> 24)};
        Require(fwrite(length, 1, 4, packets) == 4 && fwrite(packet, 1, bytes, packets) == (size_t)bytes, "packet write failed");
        Require(fwrite(output, 2, samples * channels, reference) == (size_t)(samples * channels), "reference write failed");
        Require(fwrite(input, 2, samples * channels, original) == (size_t)(samples * channels), "original write failed");
        printf("channels=%d frame=%d config=%u bytes=%d samples=%d peak=%d\n", channels, frame, packet[0] >> 3, bytes, samples, peak);
    }
    Require(fclose(packets) == 0 && fclose(reference) == 0 && fclose(original) == 0, "close output failed");
    opus_decoder_destroy(decoder);
    opus_encoder_destroy(encoder);
}

int main(int argc, char** argv) {
    Require(argc == 2, "expected output directory");
    printf("official reference %s\n", opus_get_version_string());
    Generate(argv[1], 1);
    Generate(argv[1], 2);
    return 0;
}
