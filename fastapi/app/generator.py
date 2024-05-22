from openai import OpenAI
from dotenv import load_dotenv
import requests
import json
import os
import time

load_dotenv()


def get_community_model_list():
    # https://stablediffusionapi.com/docs/miscs/model-list
    url = "https://stablediffusionapi.com/api/v4/dreambooth/model_list"

    payload = json.dumps({"key": os.getenv("STABLE_DIFFUSION_KEY")})
    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)


def generate_ai_image(keyword: str, style: str):
    # 1. given keyword from user
    # 2. ask chatgpt to complete prompt
    # 3. then ask stable-diffusion to generate the image

    start = time.time()

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "user",
                "content": f"Given the following keyword: {keyword}, generate a {style} of image. write down prompt with more details within 20 words.",
            },
        ],
        temperature=0.8,
    )

    output = completion.choices[0].message.content.strip("\n")
    output_list = output.split("\n")
    description = output_list[0]
    print(f"prompt : {description}")

    # stable diffusion

    url = "https://stablediffusionapi.com/api/v3/text2img"

    negative_words = ["nsfw", "uncensored", "cleavage", "nude", "nipples"]

    payload = json.dumps(
        {
            "key": os.getenv("STABLE_DIFFUSION_KEY"),
            "prompt": description,
            "negative_prompt": ",".join(negative_words),
            "width": "512",  # max width: 1024
            "height": "512",  # max height: 1024
            "samples": "4",  # max: 4
            "num_inference_steps": "20",
            "seed": None,  # Seed is used to reproduce results, same seed will give you same image in return again. Pass null for a random number.
            "guidance_scale": 7.5,  # Scale for classifier-free guidance (minimum: 1; maximum: 20).
            "enhance_prompot": "yes",  # (())
            "safety_checker": "yes",  # A checker for NSFW images. If such an image is detected, it will be replaced by a blank image.
            "multi_lingual": "no",
            "panorama": "no",
            "self_attention": "no",  # If you want a high quality image, set this parameter to "yes". In this case the image generation will take more time.
            "upscale": "no",  # Set this parameter to "yes" if you want to upscale the given image resolution two times (2x). If the requested resolution is 512 x 512 px, the generated image will be 1024 x 1024 px.
            "embeddings_model": None,
            "webhook": None,
            "track_id": None,
        }
    )

    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload, timeout=100)
    # response.text : str -> json.loads(response.text): dict
    img_urls = json.loads(response.text)["output"]  # "output"/"proxy_links"

    end = time.time()
    print(end - start)  # time in seconds

    return img_urls


def generate_ai_image_community_model(keyword: str, style: str):
    # 1. given keyword from user
    # 2. ask chatgpt to complete prompt (deleted)
    # 3. then ask stable-diffusion to generate the image

    start = time.time()
    client = OpenAI()

    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "user",
                "content": f"Given the following keyword: {keyword}, translate the words in English.",
            },
        ],
        temperature=0.8,
    )

    output = completion.choices[0].message.content.strip("\n")
    output_list = output.split("\n")
    keyword = output_list[0]
    print(f"prompt : {keyword}")

    # stable diffusion
    # initialize variables
    prompt = ""
    model_id = "ae-sdxl-v1"

    url = "https://stablediffusionapi.com/api/v4/dreambooth"

    negative_words = [
        "nsfw",
        "uncensored",
        "cleavage",
        "nude",
        "nipples",
        "extra fingers",
        "mutated hands",
        "poorly drawn hands",
        "poorly drawn face",
        "distorted form",
        "deformed",
        "bad crushed",
        "ugly",
        "blurry",
        "bad anatomy",
        "bad proportions",
        "extra limbs",
        "cloned face",
        "skinny",
        "glitchy",
        "double torso",
        "extra arms",
        "extra hands",
        "mangled fingers",
        "missing lips",
        "ugly face",
        "distorted face",
        "extra legs",
        "truncated image",
        "cropped image",
        "a mock-up image",
    ]

    if style == "팝아트":
        prompt = f"((pop art style)),(((illustration of Roy Lichtenstein style))), {keyword}, geometric colorful background, ink, comic book, cartoon style, half body, colors, double exposure, mixed media, intricately detailed"

    elif style == "데코":
        prompt = f"(((main style is Art Deco style))), ((Abstract, geometric abstract)), (white background), (digital printing), {keyword}, zoom out, (vivid color), (colorful), high quality, highly detail."

    elif style == "그라피티":
        prompt = f"(((graffiti style illustration))), (((white background))),(digital painting), A captivating and energetic logo featuring the name {keyword} is intricately painted in swirling, anime inspired typography, ((colorful poster color)), ((Use less color)),(Very small range of coloring), (unexpected coloring), ((paint spreading and splashing effect)), (artistic coloring), (((abstract)))"

    elif style == "키덜트":
        model_id = "nightvision-xl"
        negative_words.extend(
            [
                "Bad anatomy",
                "Bad hands",
                "Amputee",
                "Missing fingers",
                "Missing hands",
                "Missing limbs",
                "Missing arms",
                "Extra fingers",
                "Extra hands",
                "Extra limbs",
                "Mutated hands",
                "Mutated",
                "Mutation",
                "Multiple heads",
                "Malformed limbs",
                "Disfigured",
                "Poorly drawn hands",
                "Poorly drawn face",
                "Long neck",
                "Fused fingers",
                "Fused hands",
                "Dismembered",
                "Duplicatem",
                "Improper scale",
                "Ugly body",
                "Cloned face",
                "Cloned body",
                "Gross proportions",
            ]
        )
        prompt = f"((main style is kidult)), Imagine a whimsical scene featuring adorable pastel-colored {keyword} in a playful and colorful (kidult) style. Whether it's a photograph or an illustration, the focus is on the cute charm of the {keyword}, rendered in various pastel hues to evoke a sense of innocence and fun. The lighting is soft and diffused, casting gentle shadows to accentuate the textures, The perspective is childlike, capturing the world from a low angle to emphasize the wonder and imagination of childhood. The background is filled with imaginative elements like fluffy clouds, lush greenery, and perhaps hints of fantastical landscapes. Consider using a wide-angle lens to capture the expansive world of whimsy and delight."
    elif style == "라인아트":
        prompt = f"(((line art of Egon Schiele style))), ((Deconstructed minimalist line drawing)),(Drawing with emphasized lines), (white background), {keyword}, ((colorful pastel tone watercolor)), ((Use less color)),(Very small range of coloring), (unexpected coloring), ((paint spreading and splashing effect)), artistic coloring"
    elif style == "앰블럼":
        prompt = f"(((emblem logo))), ((clean and minimal logo design)), {keyword}, natural colors , text 'rabbit club' in bold font below the rabbit, (white background), (digital printing), high quality, high detail, high quality illustration"
    elif style == "스테인글라스":
        prompt = f"((main style is Stained glass, broken glass effect, Alfons Mucha style)), Stained glass {keyword} with a broken glass effect, texture-rich, mythical, radiant with energy, glowing with molecular precision, scales both iridescent and luminescent, an epitome of breathtaking beauty and divine presence, framed by volumetric light casting auras and rays, no background to enhance the vivid color reflections, stunning, unforgettable, impressive, ultra-realistic digital painting, Broken Glass effect, no background, stunning, something that even doesn't exist, mythical being, energy, molecular, textures, iridescent and luminescent scales, breathtaking beauty, pure perfection, divine presence, unforgettable, impressive, breathtaking beauty, Volumetric light, auras, rays, vivid colors reflects"
    elif style == "빈티지 포스터":
        prompt = f"(((main style is vintage poster of Joseph Christian Leyendecker style))),(old color paper texture), (vintage poster illustration), (white background),(digital painting), zoom out, full body shoot, {keyword}, detailed facial expression, High resolution illustration, sharp lines, high quality, highly detailed"
    elif style == "애니메이션":
        model_id = "dark-sushi-mix"
        negative_words.extend(
            [
                "Bad anatomy",
                "Bad hands",
                "Amputee",
                "Missing fingers",
                "Missing hands",
                "Missing limbs",
                "Missing arms",
                "Extra fingers",
                "Extra hands",
                "Extra limbs",
                "Mutated hands",
                "Mutated",
                "Mutation",
                "Multiple heads",
                "Malformed limbs",
                "Disfigured",
                "Poorly drawn hands",
                "Poorly drawn face",
                "Long neck",
                "Fused fingers",
                "Fused hands",
                "Dismembered",
                "Duplicatem",
                "Improper scale",
                "Ugly body",
                "Cloned face",
                "Cloned body",
                "Gross proportions",
            ]
        )
        prompt = f"(((main style is anime STUDIO GHIBLI))), (digital painting), close up, {keyword}, cool summer sky, sunlit sparkling background, high quality, highly detailed, (Pastel colors), (lovely atmosphere), (ink), (comic book), (cartoon style), close up, half body, color, double exposure, mixed media, intricately detailed, top quality, 4K"

    elif style == "픽셀아트":
        model_id = "pixel-art-diffusion-xl"
        negative_words.append("painting")
        prompt = f"(((main style is pixel art))), ((white background)), (digital printing), {keyword}, (high contrast), (color palette limited), ultra-fine details"

    else:
        pass

    print(model_id)
    print(prompt)
    payload = json.dumps(
        {
            "key": os.getenv("STABLE_DIFFUSION_KEY"),
            "prompt": prompt,
            "negative_prompt": ",".join(negative_words),
            "model_id": model_id,
            "width": "512",
            "height": "512",
            "samples": "4",
            "num_inference_steps": "30",
            "safety_checker": "yes",
            "enhance_prompt": "yes",
            "seed": 9885,
            "guidance_scale": 7.5,
            "multi_lingual": "no",
            "panorama": "no",
            "self_attention": "no",
            "upscale": "no",
            "embeddings_model": None,
            "lora_model": None,
            "tomesd": "yes",
            "use_karras_sigmas": "yes",
            "vae": None,
            "lora_strength": None,
            "scheduler": "DDPMScheduler",
            "webhook": None,
            "track_id": None,
        }
    )

    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload, timeout=200)
    # print(response.text)
    # response.text : str -> json.loads(response.text): dict

    # stable-diffusion api 업뎃중인듯 : 나중에 체크 필요
    try:
        img_urls = json.loads(response.text)["output"]
    except KeyError:
        img_urls = json.loads(response.text)["future_links"]

    end = time.time()
    print(end - start)  # time in seconds

    return img_urls


def upscale_from_image(img_url: str):
    start = time.time()

    url = "https://stablediffusionapi.com/api/v3/img2img"

    payload = json.dumps(
        {
            "key": os.getenv("STABLE_DIFFUSION_KEY"),
            "prompt": None,
            "negative_prompt": None,
            "init_image": img_url,
            "width": "1024",
            "height": "1024",
            "samples": "1",
            "num_inference_steps": "30",
            "safety_checker": "no",
            "enhance_prompt": "yes",
            "guidance_scale": 7.5,
            "strength": 0,
            "base64": "no",
            "seed": None,
            "webhook": None,
            "track_id": None,
        }
    )

    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload, timeout=100)
    print(response.text)
    # response.text : str -> json.loads(response.text): dict
    img_urls = json.loads(response.text)["output"]  # "output"/"proxy_links"

    end = time.time()
    print(end - start)  # time in seconds

    return img_urls

