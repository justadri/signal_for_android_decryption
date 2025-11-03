from . import decrypt_backup
from argparse import ArgumentParser
from pathlib import Path
from getpass import getpass


def main():
    parser = ArgumentParser(
        description="""
            Decrypt a Signal for Android backup file into its constituent
            SQLite database and associated files (e.g. attachments, stickers
            and avatars).
        """
    )
    parser.add_argument(
        "backup_file",
        type=Path,
        required=True,
        help="The Signal for Android backup file.",
    )
    parser.add_argument(
        "--output_directory",
        "-o",
        type=Path,
        nargs="?",
        default=Path("./out"),
        help="""
            The output directory into which the decrypted data will be written.
            Defaults to %(default)s.  This directory will be created if it does
            not exist. Existing files may be silently overwritten. Within this
            directory the following will be created. A `database.sqlite`
            containing the Signal app's SQLite database. A `preferences.json`
            file containing certain preference data held by Signal. A trio of
            directories `attachments`, `avatars` and `stickers` which contain
            binary blobs extracted from the backup. These files are named
            according to database IDs in the SQLite database.
        """,
    )
    parser.add_argument(
        "--passphrase",
        "-p",
        type=str,
        help="""
            The backup file passphrase. If this argument is not provided, the
            passphrase will be requested interactively.
        """
    )
    parser.add_argument(
        "--extract_database",
        type=bool,
        action="store_true",
        default=True,
        help="""
            Extract the message database from the backup file. Default is True.
        """
    )
    parser.add_argument(
        "--extract-attachments",
        type=bool,
        action="store_true",
        default=True,
        help="""
            Extract attachments, stickers, and avatars from the backup file.
            Default is True.
        """
    )
    parser.add_argument(
        "--extract-preferences",
        type=bool,
        action="store_true",
        default=True,
        help="""
            Extract preferences from the backup file. Default is True.
        """
    )

    args = parser.parse_args()

    if args.passphrase is None:
        args.passphrase = getpass("Backup passphrase: ")
    
    decrypt_backup.decrypt(
        args.backup_file,
        args.passphrase,
        args.output_directory,
        extract_database=args.extract_database,
        extract_attachments=args.extract_attachments,
        extract_preferences=args.extract_preferences,
    )

if __name__ == "__main__":
    main()
