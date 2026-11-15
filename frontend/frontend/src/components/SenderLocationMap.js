import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
const COUNTRY_POINTS = {
    US: { code: 'US', name: 'United States', lat: 39.8, lon: -98.6 },
    CA: { code: 'CA', name: 'Canada', lat: 56.1, lon: -106.3 },
    MX: { code: 'MX', name: 'Mexico', lat: 23.6, lon: -102.5 },
    BR: { code: 'BR', name: 'Brazil', lat: -10.8, lon: -51.9 },
    AR: { code: 'AR', name: 'Argentina', lat: -38.4, lon: -63.6 },
    CL: { code: 'CL', name: 'Chile', lat: -33.4, lon: -70.7 },
    CO: { code: 'CO', name: 'Colombia', lat: 4.6, lon: -74.1 },
    PE: { code: 'PE', name: 'Peru', lat: -9.2, lon: -75.0 },
    GB: { code: 'GB', name: 'United Kingdom', lat: 55.4, lon: -3.4 },
    IE: { code: 'IE', name: 'Ireland', lat: 53.1, lon: -8.0 },
    FR: { code: 'FR', name: 'France', lat: 46.2, lon: 2.2 },
    DE: { code: 'DE', name: 'Germany', lat: 51.2, lon: 10.5 },
    ES: { code: 'ES', name: 'Spain', lat: 40.5, lon: -3.7 },
    PT: { code: 'PT', name: 'Portugal', lat: 39.4, lon: -8.2 },
    IT: { code: 'IT', name: 'Italy', lat: 41.9, lon: 12.6 },
    NL: { code: 'NL', name: 'Netherlands', lat: 52.1, lon: 5.3 },
    BE: { code: 'BE', name: 'Belgium', lat: 50.8, lon: 4.5 },
    CH: { code: 'CH', name: 'Switzerland', lat: 46.8, lon: 8.2 },
    AT: { code: 'AT', name: 'Austria', lat: 47.5, lon: 14.6 },
    SE: { code: 'SE', name: 'Sweden', lat: 60.1, lon: 18.6 },
    NO: { code: 'NO', name: 'Norway', lat: 60.5, lon: 8.5 },
    DK: { code: 'DK', name: 'Denmark', lat: 56.3, lon: 9.5 },
    FI: { code: 'FI', name: 'Finland', lat: 64.0, lon: 26.0 },
    PL: { code: 'PL', name: 'Poland', lat: 52.0, lon: 19.1 },
    CZ: { code: 'CZ', name: 'Czechia', lat: 49.8, lon: 15.5 },
    UA: { code: 'UA', name: 'Ukraine', lat: 48.4, lon: 31.2 },
    RO: { code: 'RO', name: 'Romania', lat: 45.9, lon: 25.0 },
    GR: { code: 'GR', name: 'Greece', lat: 39.1, lon: 21.8 },
    RU: { code: 'RU', name: 'Russia', lat: 61.5, lon: 105.3 },
    TR: { code: 'TR', name: 'Türkiye', lat: 38.9, lon: 35.2 },
    IL: { code: 'IL', name: 'Israel', lat: 31.0, lon: 34.9 },
    SA: { code: 'SA', name: 'Saudi Arabia', lat: 23.9, lon: 45.1 },
    AE: { code: 'AE', name: 'United Arab Emirates', lat: 24.3, lon: 54.4 },
    EG: { code: 'EG', name: 'Egypt', lat: 26.8, lon: 30.8 },
    ZA: { code: 'ZA', name: 'South Africa', lat: -30.6, lon: 22.9 },
    NG: { code: 'NG', name: 'Nigeria', lat: 9.1, lon: 8.7 },
    KE: { code: 'KE', name: 'Kenya', lat: -0.0, lon: 37.9 },
    GH: { code: 'GH', name: 'Ghana', lat: 7.9, lon: -1.0 },
    MA: { code: 'MA', name: 'Morocco', lat: 31.8, lon: -7.1 },
    IN: { code: 'IN', name: 'India', lat: 22.6, lon: 79.0 },
    PK: { code: 'PK', name: 'Pakistan', lat: 30.4, lon: 69.3 },
    BD: { code: 'BD', name: 'Bangladesh', lat: 23.7, lon: 90.4 },
    NP: { code: 'NP', name: 'Nepal', lat: 28.4, lon: 84.1 },
    LK: { code: 'LK', name: 'Sri Lanka', lat: 7.9, lon: 80.8 },
    CN: { code: 'CN', name: 'China', lat: 35.9, lon: 104.2 },
    JP: { code: 'JP', name: 'Japan', lat: 36.2, lon: 138.3 },
    KR: { code: 'KR', name: 'South Korea', lat: 36.5, lon: 127.9 },
    TW: { code: 'TW', name: 'Taiwan', lat: 23.7, lon: 121.0 },
    HK: { code: 'HK', name: 'Hong Kong', lat: 22.3, lon: 114.2 },
    SG: { code: 'SG', name: 'Singapore', lat: 1.35, lon: 103.8 },
    MY: { code: 'MY', name: 'Malaysia', lat: 4.2, lon: 101.9 },
    ID: { code: 'ID', name: 'Indonesia', lat: -2.5, lon: 118.0 },
    PH: { code: 'PH', name: 'Philippines', lat: 12.9, lon: 121.8 },
    TH: { code: 'TH', name: 'Thailand', lat: 15.9, lon: 100.9 },
    VN: { code: 'VN', name: 'Vietnam', lat: 14.1, lon: 108.3 },
    AU: { code: 'AU', name: 'Australia', lat: -25.3, lon: 133.8 },
    NZ: { code: 'NZ', name: 'New Zealand', lat: -40.9, lon: 174.9 },
    FJ: { code: 'FJ', name: 'Fiji', lat: -17.7, lon: 178.1 },
};
const COUNTRY_ALIASES = {
    'united states of america': 'US',
    'usa': 'US',
    'uk': 'GB',
    'u.k.': 'GB',
    'uae': 'AE',
    'u.a.e.': 'AE',
    'south korea': 'KR',
    'republic of korea': 'KR',
    'russian federation': 'RU',
    'czech republic': 'CZ',
    'turkey': 'TR',
    'viet nam': 'VN',
};
const NAME_TO_CODE = Object.fromEntries(Object.values(COUNTRY_POINTS).flatMap((point) => [
    [point.name.toLowerCase(), point.code],
    [point.code.toLowerCase(), point.code],
]));
function normaliseCountry(value) {
    if (!value)
        return null;
    const raw = value.trim().toUpperCase();
    if (COUNTRY_POINTS[raw])
        return COUNTRY_POINTS[raw];
    const normalized = value.trim().toLowerCase();
    const alias = COUNTRY_ALIASES[normalized];
    const code = alias ?? NAME_TO_CODE[normalized];
    return code ? COUNTRY_POINTS[code] : null;
}
function project(lon, lat) {
    // Plate Carrée projection: x = longitude, y = latitude.
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return { left: `${x}%`, top: `${y}%` };
}
export function SenderLocationMap({ data }) {
    const rawLocations = [
        ...(data?.ips ?? []).map((item) => ({ country: item.country, id: item.ip, reputation: item.reputation_score })),
        ...(data?.domains ?? []).map((item) => ({ country: item.country, id: item.domain, reputation: item.reputation_score })),
    ];
    const locations = rawLocations
        .map((item) => ({ ...item, point: normaliseCountry(item.country) }))
        .filter((item) => Boolean(item.point));
    const unique = locations.filter((item, index, arr) => arr.findIndex((candidate) => candidate.point.code === item.point.code) === index);
    const primary = unique[0]?.point ?? null;
    return (_jsxs("section", { className: "result-location", children: [_jsxs("div", { className: "result-panel__head", children: [_jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "GEO INTELLIGENCE" }), _jsx("h2", { children: "Sender origin" })] }), _jsx("span", { className: "result-panel__tag", children: "IP / COUNTRY" })] }), _jsxs("div", { className: "result-map-shell", children: [_jsx("div", { className: "result-map-grid", "aria-hidden": "true" }), _jsx("img", { className: "result-world-map", src: "https://upload.wikimedia.org/wikipedia/commons/9/9f/BlankMap-World-Equirectangular.svg", alt: "World map" }), unique.slice(0, 5).map((location) => {
                        const position = project(location.point.lon, location.point.lat);
                        return (_jsxs("div", { className: "result-map-marker", style: position, title: `${location.point.name}${location.country ? ` · ${location.country}` : ''}`, children: [_jsx("span", { className: "result-map-marker__pulse" }), _jsx("span", { className: "result-map-marker__dot" })] }, location.point.code));
                    }), !primary && (_jsxs("div", { className: "result-map-empty", children: [_jsx("span", { children: "NO GEO LOCATION" }), _jsx("p", { children: "The backend result did not include a mappable country." })] }))] }), _jsxs("div", { className: "result-location__footer", children: [_jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "PRIMARY COUNTRY" }), _jsx("strong", { children: primary?.name ?? 'Not available' })] }), _jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "POINTS" }), _jsx("strong", { children: unique.length || '—' })] })] }), _jsx("p", { className: "result-location__note", children: "Location is shown at country level from the backend threat-intelligence data. The marker uses the country's geographic centroid; it does not claim a street address or exact physical sender location." })] }));
}
