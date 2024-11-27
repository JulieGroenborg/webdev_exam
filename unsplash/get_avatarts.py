import os
import requests
import time
import x

# Unsplash API key
url = 'https://api.unsplash.com/photos/random'
headers = {
    'Authorization': f'Client-ID {x.UNSPLASH_ACCESS_KEY}'
}

# Folder to save images
save_folder = '../images'
os.makedirs(save_folder, exist_ok=True)

def get_random_images(total_images=100, batch_size=30):
    images = []
    while len(images) < total_images:
        count = min(batch_size, total_images - len(images))
        params = {
            'count': count
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            images.extend(response.json())
        else:
            print(f"Failed to fetch images: {response.status_code}")
            break
        time.sleep(1)  # Respect API rate limits
    return images[:total_images]

def download_image(image_url, save_path):
    try:
        img_data = requests.get(image_url).content
        with open(save_path, 'wb') as handler:
            handler.write(img_data)
        print(f"Downloaded {save_path}")
    except Exception as e:
        print(f"Error downloading {image_url}: {e}")

# Fetch 100 random images and download them
images = get_random_images(100)

for idx, img in enumerate(images):
    img_url = img['urls']['regular']  # Get the image URL
    img_name = f"image_{idx + 1}.jpg"
    save_path = os.path.join(save_folder, img_name)
    download_image(img_url, save_path)



