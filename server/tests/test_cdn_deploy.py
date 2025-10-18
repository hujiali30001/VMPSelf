from tools.deploy_cdn import DeployConfig, generate_nginx_config


def test_generate_nginx_config_includes_token_and_origin():
    config = DeployConfig(
        origin_host="origin.local",
        origin_port=8443,
        edge_token="edge-secret",
        allow_http=True,
    )

    nginx_config = generate_nginx_config(config.to_deployment_config())

    assert "listen 80;" in nginx_config
    assert "listen 443 ssl" in nginx_config
    assert "proxy_pass https://origin.local:8443;" in nginx_config
    assert "proxy_set_header X-Edge-Token \"edge-secret\";" in nginx_config


def test_generate_nginx_config_tcp_mode():
    config = DeployConfig(
        origin_host="origin.internal",
        origin_port=7000,
        listen_port=9000,
        mode="tcp",
    )

    nginx_config = generate_nginx_config(config.to_deployment_config())

    assert "stream {" in nginx_config
    assert "server origin.internal:7000;" in nginx_config
    assert "listen 9000;" in nginx_config
    assert "proxy_pass vmp_origin;" in nginx_config
