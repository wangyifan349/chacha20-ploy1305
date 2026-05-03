#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
interactive_file_finder_en.py

Purpose:
    This script is an interactive command-line file search tool.

    It recursively scans a user-specified directory and searches for files based
    on filename-related conditions first. The supported filename conditions are:
        1. Exact filename
        2. Filename prefix
        3. Filename suffix
        4. Text contained anywhere in the filename

    Filename-based filtering is mandatory. The user must provide at least one
    filename condition before starting a search.

    Optionally, the user may also provide a file hash value. The user does not
    need to specify the hash algorithm. The script automatically infers possible
    hash algorithms from the length of the provided hexadecimal hash string and
    tries all compatible algorithms available in the current Python hashlib
    environment.

Typical supported hash algorithms include:
    md5
    sha1
    sha224
    sha256
    sha384
    sha512
    sha3_224
    sha3_256
    sha3_384
    sha3_512
    blake2s
    blake2b
    shake_128
    shake_256

Important notes:
    1. At least one filename condition is required.
    2. Hash matching is optional.
    3. If a hash value is provided, the script applies hash matching only after
       a file has already matched the filename conditions.
    4. Multiple hash algorithms may produce hexadecimal digests with the same
       length. For example, sha256, sha3_256, and blake2s all produce 64-character
       hexadecimal digests. In such cases, this script tries all compatible
       algorithms.
    5. SHAKE algorithms are variable-length output algorithms. This script uses
       the length of the provided hash string to determine the required output
       byte length.
    6. Hash matching reads the full content of each filename-matched file, so it
       can be slower than filename-only searching, especially for large files.
    7. After each search, the program pauses and waits for the user to press
       Enter. This prevents the program from closing immediately.

How to run:
    python interactive_file_finder_en.py

Typical usage flow:
    1. Run the script.
    2. Select "1. Configure search conditions".
    3. Enter the root directory to search.
    4. Enter at least one filename condition.
    5. Decide whether to provide a hash value.
    6. Select "3. Start search".
    7. Review the matched file paths and, if hash matching was enabled, the
       matched hash algorithm names.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional


CHUNK_SIZE = 1024 * 1024                                           # Read 1 MB per chunk to avoid loading large files into memory


@dataclass
class SearchConfiguration:
    """
    Stores all search options entered by the user.
    """
    root_directory: str                                             # Root directory to search recursively
    exact_filename: Optional[str]                                   # Exact filename, for example: test.txt
    filename_prefix: Optional[str]                                  # Filename prefix, for example: IMG_
    filename_suffix: Optional[str]                                  # Filename suffix, for example: .jpg
    filename_contains: Optional[str]                                # Text contained in the filename, for example: backup
    target_hash: Optional[str]                                      # Target hash value entered by the user
    ignore_case: bool                                               # Whether filename matching should ignore case


@dataclass
class SearchResult:
    """
    Stores one matched search result.
    """
    file_path: str                                                  # Full path of the matched file
    matched_hash_algorithms: List[str]                              # Matched hash algorithm names; empty if hash matching is disabled


def pause_after_search() -> None:
    """
    Pauses after a search so the program does not exit or continue immediately.
    """
    input("\nSearch finished. Press Enter to return to the main menu...")  # Wait for user confirmation before returning to the menu


def prompt_optional_input(prompt_text: str) -> Optional[str]:
    """
    Reads optional user input.

    Returns None if the user presses Enter without typing anything.
    """
    user_input = input(prompt_text).strip()                         # Remove leading and trailing whitespace
    return user_input if user_input else None                       # Convert an empty string to None


def prompt_yes_no(prompt_text: str, default: bool = False) -> bool:
    """
    Reads a yes/no answer from the user.
    """
    option_hint = "Y/n" if default else "y/N"                       # Show the default option in the prompt

    while True:
        user_input = input(f"{prompt_text} [{option_hint}]: ").strip().lower()

        if not user_input:
            return default                                          # Use the default value if the user simply presses Enter

        if user_input in {"y", "yes", "1", "true"}:
            return True                                             # Accept common affirmative inputs

        if user_input in {"n", "no", "0", "false"}:
            return False                                            # Accept common negative inputs

        print("Please enter y or n.")                               # Keep asking until a valid answer is provided


def normalize_hash_value(hash_value: str) -> str:
    """
    Normalizes a hash string entered by the user.

    Supported input formats include:
        aabbcc
        AA:BB:CC
        AA BB CC
        AA-BB-CC
    """
    return (
        hash_value.strip()                                          # Remove leading and trailing whitespace
        .replace(":", "")                                           # Remove colon separators
        .replace(" ", "")                                           # Remove space separators
        .replace("-", "")                                           # Remove dash separators
        .lower()                                                    # Convert to lowercase for case-insensitive comparison
    )


def is_hex_string(value: str) -> bool:
    """
    Checks whether a string is a valid hexadecimal string.
    """
    normalized_value = normalize_hash_value(value)                  # Normalize the input first

    if not normalized_value:
        return False                                                # Empty strings are not valid hash values

    try:
        int(normalized_value, 16)                                   # Try parsing the string as hexadecimal
        return True
    except ValueError:
        return False                                                # Return False if non-hexadecimal characters are found


def is_shake_algorithm(algorithm_name: str) -> bool:
    """
    Checks whether the algorithm is a SHAKE variable-length hash algorithm.
    """
    return algorithm_name.lower() in {"shake_128", "shake_256"}     # SHAKE hexdigest() requires an output byte length


def get_candidate_hash_algorithms(target_hash: str) -> List[str]:
    """
    Infers possible hash algorithms from the length of the target hash.

    Details:
        1. Fixed-length hash algorithms expose digest_size.
        2. For example, sha256 has a digest_size of 32 bytes, which means
           its hexadecimal digest length is 64 characters.
        3. SHAKE algorithms have variable-length output, so they are candidates
           when the target hash has an even number of hexadecimal characters.
    """
    normalized_target_hash = normalize_hash_value(target_hash)       # Normalize the target hash
    target_hex_length = len(normalized_target_hash)                 # Count hexadecimal characters
    available_algorithms = sorted(hashlib.algorithms_available)     # Algorithms available in the current Python environment
    candidate_algorithms: List[str] = []                            # Store compatible algorithm names

    for algorithm_name in available_algorithms:
        try:
            hash_object = hashlib.new(algorithm_name)               # Create a hash object to inspect digest_size
        except ValueError:
            continue                                                # Skip unsupported or invalid algorithm aliases

        if is_shake_algorithm(algorithm_name):
            if target_hex_length % 2 == 0:
                candidate_algorithms.append(algorithm_name)         # SHAKE can output any byte length if the hex length is even
            continue

        digest_byte_size = hash_object.digest_size                  # Fixed-length digest size in bytes
        digest_hex_length = digest_byte_size * 2                    # One byte equals two hexadecimal characters

        if digest_hex_length == target_hex_length:
            candidate_algorithms.append(algorithm_name)             # Only algorithms with matching digest length are useful

    return sorted(set(candidate_algorithms))                        # Remove duplicates and return a stable sorted list


def calculate_hashes_for_file(
    file_path: str,
    candidate_algorithms: List[str],
    target_hash: str,
) -> List[str]:
    """
    Calculates candidate hashes for a single file and returns matched algorithms.

    The file is read only once. All candidate hash objects are updated with the
    same chunks while the file is being read. This is more efficient than reading
    the same file once for every algorithm.
    """
    normalized_target_hash = normalize_hash_value(target_hash)       # Normalize the target hash
    target_hex_length = len(normalized_target_hash)                 # Used to determine SHAKE output byte length
    hash_objects: Dict[str, object] = {}                            # Map algorithm names to hash objects
    matched_algorithms: List[str] = []                              # Store algorithms whose digest matches the target hash

    for algorithm_name in candidate_algorithms:
        try:
            hash_objects[algorithm_name] = hashlib.new(algorithm_name)
        except ValueError:
            continue                                                # Skip unexpected invalid algorithms for safety

    if not hash_objects:
        return matched_algorithms                                   # No usable algorithms, so nothing can match

    try:
        with open(file_path, "rb") as file_object:                  # Open the file in binary mode
            while True:
                file_chunk = file_object.read(CHUNK_SIZE)           # Read the file in chunks

                if not file_chunk:
                    break                                           # Stop when the end of the file is reached

                for hash_object in hash_objects.values():
                    hash_object.update(file_chunk)                  # Update every candidate hash object with the same chunk

    except PermissionError:
        print(f"[Skipped] Permission denied: {file_path}")          # Skip files that cannot be read due to permissions
        return matched_algorithms

    except OSError as error:
        print(f"[Skipped] Cannot read: {file_path}. Reason: {error}")  # Skip files that cannot be read for OS-related reasons
        return matched_algorithms

    for algorithm_name, hash_object in hash_objects.items():
        if is_shake_algorithm(algorithm_name):
            shake_output_bytes = target_hex_length // 2             # SHAKE hexdigest() expects an output length in bytes
            calculated_hash = hash_object.hexdigest(shake_output_bytes)
        else:
            calculated_hash = hash_object.hexdigest()               # Fixed-length algorithms output the full hexadecimal digest

        if normalize_hash_value(calculated_hash) == normalized_target_hash:
            matched_algorithms.append(algorithm_name)               # Record the algorithm if the digest matches

    return matched_algorithms


def filename_matches_configuration(
    filename: str,
    configuration: SearchConfiguration,
) -> bool:
    """
    Checks whether a filename satisfies the configured filename conditions.

    If multiple filename conditions are provided, all of them must match.
    """
    current_filename = filename                                     # Filename currently being checked
    exact_filename = configuration.exact_filename                   # Exact filename condition
    filename_prefix = configuration.filename_prefix                 # Prefix condition
    filename_suffix = configuration.filename_suffix                 # Suffix condition
    filename_contains = configuration.filename_contains             # Contains-text condition

    if configuration.ignore_case:
        current_filename = current_filename.lower()                 # Convert filename to lowercase
        exact_filename = exact_filename.lower() if exact_filename else None
        filename_prefix = filename_prefix.lower() if filename_prefix else None
        filename_suffix = filename_suffix.lower() if filename_suffix else None
        filename_contains = filename_contains.lower() if filename_contains else None

    if exact_filename and current_filename != exact_filename:
        return False                                                # Exact filename does not match

    if filename_prefix and not current_filename.startswith(filename_prefix):
        return False                                                # Prefix does not match

    if filename_suffix and not current_filename.endswith(filename_suffix):
        return False                                                # Suffix does not match

    if filename_contains and filename_contains not in current_filename:
        return False                                                # Required substring is not present

    return True                                                     # All configured filename conditions match


def find_matching_files(configuration: SearchConfiguration) -> List[SearchResult]:
    """
    Recursively searches for files based on the provided configuration.

    Search flow:
        1. Traverse the directory tree with os.walk.
        2. Filter files by filename conditions first.
        3. If a target hash was provided, calculate candidate hashes.
        4. Return matched file paths and matched hash algorithm names.
    """
    search_results: List[SearchResult] = []                         # Store all matched results
    target_hash = configuration.target_hash                         # Target hash value, or None
    candidate_algorithms: List[str] = []                            # Candidate hash algorithms

    if target_hash:
        candidate_algorithms = get_candidate_hash_algorithms(target_hash)

        if not candidate_algorithms:
            print("\nNo candidate hash algorithms were found for this hash length.")
            return search_results

    for current_directory, _, filenames in os.walk(configuration.root_directory):
        for filename in filenames:
            file_path = os.path.join(current_directory, filename)   # Build the full file path

            if not filename_matches_configuration(filename, configuration):
                continue                                            # Skip files that do not match filename conditions

            matched_hash_algorithms: List[str] = []                 # Hash algorithms matched by the current file

            if target_hash:
                matched_hash_algorithms = calculate_hashes_for_file(
                    file_path=file_path,
                    candidate_algorithms=candidate_algorithms,
                    target_hash=target_hash,
                )

                if not matched_hash_algorithms:
                    continue                                        # When hash matching is enabled, skip non-matching files

            search_results.append(
                SearchResult(
                    file_path=file_path,
                    matched_hash_algorithms=matched_hash_algorithms,
                )
            )

    return search_results


def prompt_search_configuration() -> SearchConfiguration:
    """
    Interactively collects the search configuration from the user.
    """
    print("\n========== Configure Search Conditions ==========\n")

    while True:
        root_directory = input("Enter the directory to search: ").strip().strip('"').strip("'")

        if os.path.isdir(root_directory):
            break                                                   # Continue only if the directory exists

        print("The directory does not exist. Please try again.")     # Ask again if the directory is invalid

    print("\nAt least one filename condition is required.")
    print("You may enter an exact filename, prefix, suffix, or contained text.")
    print("Press Enter to skip any condition you do not need.\n")

    while True:
        exact_filename = prompt_optional_input("Exact filename, for example test.txt: ")
        filename_prefix = prompt_optional_input("Filename prefix, for example IMG_: ")
        filename_suffix = prompt_optional_input("Filename suffix, for example .jpg / .zip / .txt: ")
        filename_contains = prompt_optional_input("Text contained in filename, for example backup / invoice: ")

        if exact_filename or filename_prefix or filename_suffix or filename_contains:
            break                                                   # Require at least one filename condition

        print("\nYou must provide at least one filename condition. Please try again.\n")

    ignore_case = prompt_yes_no("Should filename matching ignore case?", default=True)

    target_hash: Optional[str] = None                               # Hash matching is disabled by default

    if prompt_yes_no("Do you also want to search by hash value?", default=False):
        while True:
            raw_hash_value = input("Enter the hash value. You do not need to specify the algorithm: ").strip()

            if is_hex_string(raw_hash_value):
                target_hash = normalize_hash_value(raw_hash_value)  # Store the normalized hash value
                break

            print("Invalid hash format. Please enter a hexadecimal hash string.")

    return SearchConfiguration(
        root_directory=root_directory,
        exact_filename=exact_filename,
        filename_prefix=filename_prefix,
        filename_suffix=filename_suffix,
        filename_contains=filename_contains,
        target_hash=target_hash,
        ignore_case=ignore_case,
    )


def print_configuration_summary(configuration: SearchConfiguration) -> None:
    """
    Prints a summary of the current search configuration.
    """
    print("\n========== Current Search Conditions ==========\n")
    print(f"Search directory: {configuration.root_directory}")
    print(f"Exact filename: {configuration.exact_filename or 'Not set'}")
    print(f"Prefix: {configuration.filename_prefix or 'Not set'}")
    print(f"Suffix: {configuration.filename_suffix or 'Not set'}")
    print(f"Contains text: {configuration.filename_contains or 'Not set'}")
    print(f"Ignore case: {'Yes' if configuration.ignore_case else 'No'}")

    if configuration.target_hash:
        candidate_algorithms = get_candidate_hash_algorithms(configuration.target_hash)
        print(f"Target hash: {configuration.target_hash}")
        print(f"Candidate algorithms: {', '.join(candidate_algorithms) if candidate_algorithms else 'None'}")
    else:
        print("Hash matching: Disabled")


def print_search_results(search_results: List[SearchResult]) -> None:
    """
    Prints the search results.
    """
    print("\n========== Search Results ==========\n")

    if not search_results:
        print("No matching files were found.")
        return

    print(f"Found {len(search_results)} matching file(s):\n")

    for index, search_result in enumerate(search_results, start=1):
        print(f"{index}. {search_result.file_path}")

        if search_result.matched_hash_algorithms:
            algorithms_text = ", ".join(search_result.matched_hash_algorithms)
            print(f"   Matched hash algorithm(s): {algorithms_text}")


def print_supported_hash_algorithms() -> None:
    """
    Prints hash algorithms supported by the current Python environment.
    """
    print("\n========== Hash Algorithms Supported by Current Python ==========\n")

    for algorithm_name in sorted(hashlib.algorithms_available):
        print(f"  {algorithm_name}")


def run_main_menu() -> None:
    """
    Runs the interactive main menu.
    """
    configuration: Optional[SearchConfiguration] = None              # Current search configuration, initially empty

    while True:
        print("\n========== File Finder ==========")
        print("1. Configure search conditions")
        print("2. View current search conditions")
        print("3. Start search")
        print("4. View hash algorithms supported by current Python")
        print("5. Exit")

        menu_choice = input("\nChoose an option [1-5]: ").strip()

        if menu_choice == "1":
            configuration = prompt_search_configuration()           # Start the configuration workflow

        elif menu_choice == "2":
            if configuration is None:
                print("\nNo search conditions have been configured yet.")
            else:
                print_configuration_summary(configuration)

        elif menu_choice == "3":
            if configuration is None:
                print("\nPlease configure search conditions first.")
                continue

            print_configuration_summary(configuration)

            if not prompt_yes_no("\nStart searching now?", default=True):
                continue

            print("\nSearching. Please wait...\n")

            search_results = find_matching_files(configuration)     # Execute the search
            print_search_results(search_results)                    # Display the results
            pause_after_search()                                    # Pause after the search instead of exiting

        elif menu_choice == "4":
            print_supported_hash_algorithms()

        elif menu_choice == "5":
            print("\nExited.")
            break

        else:
            print("\nInvalid option. Please enter a number from 1 to 5.")


def main() -> None:
    """
    Program entry point.
    """
    try:
        run_main_menu()                                             # Start the interactive menu
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")                   # Friendly message for Ctrl+C
        input("Press Enter to exit...")                             # Pause before exit


if __name__ == "__main__":
    main()
