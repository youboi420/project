#include <stdio.h>

int main() {
    // Specify the file path
    const char* filepath = "folder1/folder2/file.txt";

    // Open the file in write mode
    FILE* file = fopen(filepath, "w");

    // Check if the file is opened successfully
    if (file == NULL) {
        fprintf(stderr, "Error opening the file %s\n", filepath);
        return 1; // Return an error code
    }

    // Write "Hello, World!" to the file
    fprintf(file, "Hello, World!\n");

    // Close the file
    fclose(file);

    printf("Data written to %s successfully.\n", filepath);

    return 0; // Return success code
}
