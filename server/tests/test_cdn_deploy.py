from tools.deploy_cdn import DeployConfig, generate_nginx_config


def test_generate_nginx_config_includes_token_and_origin():
    config = DeployConfig(
        origin_host="origin.local",
        origin_port=8443,
        edge_token="edge-secret",
        allow_http=True,
    )

    nginx_config = generate_nginx_config(config)

    assert "listen 80;" in nginx_config
    assert "listen 443 ssl" in nginx_config
    assert "proxy_pass https://origin.local:8443;" in nginx_config
    assert "proxy_set_header X-Edge-Token \"edge-secret\";" in nginx_config
