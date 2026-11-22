from app.geo.geo_resolver import GeoResolver


print("=" * 70)
print("GEO REGION RESOLVER TEST")
print("=" * 70)


test_regions = [
    "North America",
    "Europe",
    "South Asia",
    "East Asia",
    "Southeast Asia",
    "Middle East",
    "Oceania",
]


for index, region in enumerate(
    test_regions,
    start=1,
):

    print("\n" + "-" * 70)

    print(f"TEST {index}")

    print(
        "Input Region:",
        region,
    )

    result = GeoResolver.resolve_region(
        region
    )

    print(
        "Canonical Region:",
        result["region"],
    )

    print(
        "Continent:",
        result["continent"],
    )

    print(
        "Countries:",
        result["countries"],
    )


print("\n")
print("=" * 70)
print("GEO REGION RESOLVER TEST COMPLETED")
print("=" * 70)