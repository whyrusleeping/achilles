# achilles

A fast lightweight labeler.

## How to

Create a keypair

```
achilles generate-key
```

Adjust your did document to point to your domain (must be the domain of the machine the labeler will run on)

```
achilles adjust-did --auth=bsky.auth --labeler-host="https://labels.sexy.social --private-key=priv.key
```

Create your label definitions file, for example:

```
{
  "$type": "app.bsky.labeler.service",
  "policies": {
    "labelValueDefinitions": [
      {
        "adultOnly": false,
        "blurs": "content",
        "defaultSetting": "warn",
        "identifier": "bad",
        "locales": [
          {
            "description": "Bad accounts",
            "lang": "en",
            "name": "Quite Bad"
          }
        ],
        "severity": "alert"
      }
    ],
    "labelValues": [
      "bad"
    ]
  }
}
```

Now publish that record:

```
achilles setup-account labels.json
```

Finally, run the server:

```
achilles --domain=labels.sexy.social --tls --private-key=priv.key
```

### License

MIT
