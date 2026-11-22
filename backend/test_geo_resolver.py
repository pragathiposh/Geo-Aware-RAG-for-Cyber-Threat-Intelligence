from app.geo.geo_resolver import GeoResolver


print("=" * 70)
print("GEO RESOLVER TEST")
print("=" * 70)


test_countries = [
    "US",
    "USA",
    "United States",
    "United States of America",
    "India",
    "UK",
    "Canada",
    "Australia",
    "Germany",
    "UAE",
]


for index, country in enumerate(
    test_countries,
    start=1,
):

    print("\n" + "-" * 70)

    print(f"TEST {index}")

    print(
        "Input:",
        country,
    )

    result = GeoResolver.resolve(
        country
    )

    print(
        "Canonical Country:",
        result["country"],
    )

    print(
        "Region:",
        result["region"],
    )

    print(
        "Continent:",
        result["continent"],
    )


print("\n")
print("=" * 70)
print("GEO RESOLVER TEST COMPLETED")
print("=" * 70)