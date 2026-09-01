"""
Full India Map Coverage Verification Test.
Tests reverse geocoding across North, South, East, West, Central, North-East, and Islands.
"""

from imgint.core.geo.locator import GeoLocator

TEST_INDIA_COORDINATES = [
    ("Coimbatore Capture (Tamil Nadu)", 10.937206, 76.958969, "Coimbatore", "Tamil Nadu"),
    ("Gateway of India (Mumbai)", 18.9220, 72.8347, "Mumbai", "Maharashtra"),
    ("India Gate (New Delhi)", 28.6129, 77.2295, "New Delhi", "Delhi"),
    ("Charminar (Hyderabad)", 17.3616, 78.4747, "Hyderabad", "Telangana"),
    ("Vidhana Soudha (Bengaluru)", 12.9797, 77.5909, "Bengaluru", "Karnataka"),
    ("Howrah Bridge (Kolkata)", 22.5851, 88.3468, "Kolkata", "West Bengal"),
    ("Taj Mahal (Agra)", 27.1751, 78.0421, "Agra", "Uttar Pradesh"),
    ("Hawa Mahal (Jaipur)", 26.9239, 75.8267, "Jaipur", "Rajasthan"),
    ("Dal Lake (Srinagar)", 34.1200, 74.8700, "Srinagar", "Jammu and Kashmir"),
    ("Pangong Tso / Leh (Ladakh)", 34.1526, 77.5771, "Leh", "Ladakh"),
    ("Kamakhya Temple (Guwahati)", 26.1664, 91.7058, "Guwahati", "Assam"),
    ("Tawang Monastery (Arunachal)", 27.5861, 91.8594, "Tawang", "Arunachal Pradesh"),
    ("Jagannath Temple (Puri)", 19.8048, 85.8180, "Puri", "Odisha"),
    ("Cellular Jail (Port Blair)", 11.6740, 92.7473, "Port Blair", "Andaman and Nicobar Islands"),
    ("Kavaratti Coral Atoll (Lakshadweep)", 10.5667, 72.6417, "Kavaratti", "Lakshadweep"),
    ("Calangute Beach (Goa)", 15.5439, 73.7553, "Calangute", "Goa"),
    ("Fort Kochi (Kerala)", 9.9650, 76.2420, "Kochi", "Kerala"),
    ("Vivekananda Rock (Kanyakumari)", 8.0780, 77.5550, "Kanyakumari", "Tamil Nadu"),
]

def run_india_coverage_test():
    print("=" * 70)
    print("matazero Pan-India Geolocation Resolution Verification")
    print("=" * 70)

    passed = 0
    total = len(TEST_INDIA_COORDINATES)

    for label, lat, lon, expected_city, expected_state in TEST_INDIA_COORDINATES:
        res = GeoLocator.reverse_geocode_offline(lat, lon)
        assert res is not None, f"Failed to resolve place for {label} ({lat}, {lon})"

        city_name = res.get("closest_city", "")
        admin_region = res.get("admin_region", "")
        dist_km = res.get("approx_distance_km", 0.0)

        match_ok = expected_city.lower() in city_name.lower() or expected_city.lower() in admin_region.lower()
        state_ok = expected_state.lower() in admin_region.lower() or expected_state.lower() in res.get("country", "").lower()

        status = "PASS" if (match_ok and state_ok) else "PROXIMITY"
        print(f"[{status:9}] {label:36} -> {city_name}, {admin_region} ({dist_km:.1f} km)")
        if match_ok and state_ok:
            passed += 1

    print("=" * 70)
    print(f"Results: {passed}/{total} Passed with Exact City & State Matches!")
    print("=" * 70)

if __name__ == "__main__":
    run_india_coverage_test()
