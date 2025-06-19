import os
import subprocess
import boto3
import dotenv

dotenv.load_dotenv()

# === Configuration ===
LOCAL_VIDEO_DIR = os.environ.get("LOCAL_VIDEO_DIR")
BUCKET_NAME = os.environ.get("BUCKET_NAME")
AWS_REGION = os.environ.get("AWS_REGION")
THUMBNAIL_TIME = os.environ.get("THUMBNAIL_TIME", default="00:00:01")  # 1 second

VIDEO_SUFFIX = os.environ.get("VIDEO_SUFFIX", default=".mp4")
THUMB_SUFFIX = os.environ.get("THUMB_SUFFIX", default=".jpg")

s3 = boto3.client("s3", region_name=AWS_REGION)


def faststart_video(video_path):
    temp_path = video_path + ".temp.mp4"
    print(f"  ⚙️  Applying +faststart to: {os.path.basename(video_path)}")
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-i",
                video_path,
                "-movflags",
                "+faststart",
                "-c",
                "copy",
                temp_path,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.replace(temp_path, video_path)
        print("  ✅ faststart applied successfully.")
    except subprocess.CalledProcessError:
        print("  ❌ Failed to apply faststart.")
        if os.path.exists(temp_path):
            os.remove(temp_path)


def generate_thumbnail(video_path, thumb_path):
    subprocess.run(
        [
            "ffmpeg",
            "-i",
            video_path,
            "-ss",
            THUMBNAIL_TIME,
            "-vframes",
            "1",
            "-q:v",
            "2",
            thumb_path,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def upload_to_s3(file_path, key, content_type):
    s3.upload_file(file_path, BUCKET_NAME, key, ExtraArgs={"ContentType": content_type})
    print(f"  ☁️  Uploaded: {key}")


def thumbnail_exists_on_s3(video_filename):
    thumb_key = os.path.splitext(video_filename)[0] + THUMB_SUFFIX
    try:
        s3.head_object(Bucket=BUCKET_NAME, Key=thumb_key)
        return True
    except s3.exceptions.ClientError:
        return False


def main():
    for filename in os.listdir(LOCAL_VIDEO_DIR):
        if not filename.lower().endswith(VIDEO_SUFFIX):
            continue
        if filename.startswith("._"):  # skip Mac metadata files
            continue

        video_path = os.path.join(LOCAL_VIDEO_DIR, filename)
        thumb_path = os.path.join(
            LOCAL_VIDEO_DIR, os.path.splitext(filename)[0] + THUMB_SUFFIX
        )
        video_key = filename

        print(f"\n📂 Processing video: {filename}")

        # Step 1: Apply faststart
        faststart_video(video_path)

        # Step 2: Upload video to S3
        upload_to_s3(video_path, video_key, "video/mp4")

        # Step 3: Handle thumbnail
        if thumbnail_exists_on_s3(filename):
            print("  ⏭️  Thumbnail already exists on S3.")
            continue

        try:
            generate_thumbnail(video_path, thumb_path)
            upload_to_s3(
                thumb_path, os.path.splitext(filename)[0] + THUMB_SUFFIX, "image/jpeg"
            )
        finally:
            if os.path.exists(thumb_path):
                os.remove(thumb_path)


if __name__ == "__main__":
    main()
