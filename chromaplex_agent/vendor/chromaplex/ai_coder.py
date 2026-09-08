"""AI-assisteret CPL kodegenerering."""

import os
import sys

_MAX_PROMPT_LENGTH = 10_000


def _fallback_cpl() -> str:
    return (
        "// Lokal CPL-skabelon (AI-klient er ikke installeret)\n"
        "potens e = 7;\n"
        "skriv_voxel(0,0,0) {\n"
        "    kanal rød = e;\n"
        "}\n"
    )

def generate_cpl_from_prompt(prompt: str) -> str:
    """Generer CPL kode fra en naturlig-sprog beskrivelse."""
    if not isinstance(prompt, str):
        raise TypeError("prompt skal være en tekststreng")
    if not prompt.strip():
        raise ValueError("prompt må ikke være tom")
    if len(prompt) > _MAX_PROMPT_LENGTH:
        raise ValueError("prompt er for lang")

    try:
        from openai import OpenAI
    except ImportError:
        return _fallback_cpl()

    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("CHROMAPLEX_OPENAI_MODEL")
    if not api_key or not model:
        return (
            "// AI-generering er ikke konfigureret. "
            "Sæt OPENAI_API_KEY og CHROMAPLEX_OPENAI_MODEL.\n"
        )

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": (
                    "Du er en CPL (ChromaPlex Language) ekspert. "
                    "Generer KUN gyldig CPL kode. Brug: potens, tal, streng, "
                    "skriv_voxel, kanal, rød, grøn, blå, violet."
                )},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        content = response.choices[0].message.content
        return content if content else "// AI-tjenesten returnerede intet indhold.\n"
    except Exception:
        return "// AI-generering mislykkedes. Se lokal logning for fejlsøgning.\n"


def main():
    if len(sys.argv) < 2:
        print("Brug: chromaplex-ai 'beskrivelse af problem'")
        return
    prompt = " ".join(sys.argv[1:])
    cpl_code = generate_cpl_from_prompt(prompt)
    print(cpl_code)


if __name__ == "__main__":
    main()
