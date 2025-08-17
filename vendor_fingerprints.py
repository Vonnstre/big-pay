# Minimal vendor fingerprints for takeover/error banners (expandable)

VENDORS = {
    "aws_s3": {
        "cname_contains": [".s3.amazonaws.com", ".s3-website"],
        "body_contains": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "azure": {
        "cname_contains": [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"],
        "body_contains": ["404 Web Site not found", "Error 404 - Web app not found"]
    },
    "github_pages": {
        "cname_contains": [".github.io"],
        "body_contains": ["There isn’t a GitHub Pages site here", "Repository not found"]
    },
    "heroku": {
        "cname_contains": [".herokudns.com", ".herokuapp.com"],
        "body_contains": ["no such app", "heroku | error"]
    },
    "vercel": {
        "cname_contains": [".vercel-dns.com", ".zeit.world", ".vercel.app"],
        "body_contains": ["DEPLOYMENT_NOT_FOUND", "The deployment must be ready", "Vercel 404"]
    },
    "netlify": {
        "cname_contains": [".netlify.app"],
        "body_contains": ["Not Found - Request ID", "No Such App"]
    },
    "fastly": {
        "cname_contains": [".fastly.net"],
        "body_contains": ["Fastly error: unknown domain"]
    },
    "readme": {
        "cname_contains": [".readme.io"],
        "body_contains": ["Project doesnt exist", "We couldn't find the page you were looking for"]
    },
    "zendesk": {
        "cname_contains": [".zendesk.com"],
        "body_contains": ["Help Center Closed", "Page not found"]
    },
    "surge": {
        "cname_contains": [".surge.sh"],
        "body_contains": ["project not found"]
    }
}
