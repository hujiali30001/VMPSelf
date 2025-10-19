from tools.deploy_cdn import DeployConfig, PortMappingConfig, generate_nginx_config


def test_generate_nginx_config_includes_token_and_origin():
    config = DeployConfig(
        origin_host="origin.local",
        origin_port=8443,
        edge_token="edge-secret",
        allow_http=True,
    )

    nginx_config = generate_nginx_config(config.to_deployment_config())

    assert nginx_config.startswith("proxy_cache_path /var/cache/nginx/vmp")
    assert "    proxy_cache_path" not in nginx_config
    assert nginx_config.count("server {") == 2
    assert "listen 80;" in nginx_config
    assert "listen 443 ssl;" in nginx_config
    assert "http2 on;" in nginx_config
    assert nginx_config.count("proxy_pass https://origin.local:8443;") == 2
    assert nginx_config.count("proxy_set_header X-Edge-Token \"edge-secret\";") == 2


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
    assert "proxy_pass vmp_origin_0;" in nginx_config


def test_generate_nginx_config_tcp_mode_with_proxy_protocol():
    config = DeployConfig(
        origin_host="origin.internal",
        origin_port=7000,
        listen_port=9000,
        mode="tcp",
    )
    deployment_config = config.to_deployment_config()
    deployment_config.proxy_protocol = True

    nginx_config = generate_nginx_config(deployment_config)

    assert "listen 9000;" in nginx_config
    assert "proxy_protocol on;" not in nginx_config
    assert "listen 9000 proxy_protocol" not in nginx_config


def test_generate_nginx_config_http_only_single_listen():
    config = DeployConfig(
        origin_host="origin.http",
        origin_port=8080,
        listen_port=80,
        allow_http=True,
    )

    nginx_config = generate_nginx_config(config.to_deployment_config())

    assert nginx_config.count("listen 80;") == 1
    assert "listen 80 ssl" not in nginx_config
    assert "ssl_certificate" not in nginx_config
    assert "http2 on;" not in nginx_config


def test_generate_nginx_config_multiple_http_mappings():
    config = DeployConfig(
        origin_host="origin.multi",
        origin_port=8443,
        listen_port=443,
        allow_http=False,
        port_mappings=[
            PortMappingConfig(listen_port=443, origin_port=8443, allow_http=False),
            PortMappingConfig(listen_port=8080, origin_port=8000, allow_http=True),
        ],
    )

    nginx_config = generate_nginx_config(config.to_deployment_config())

    assert nginx_config.count("server {") == 2
    assert "listen 443 ssl;" in nginx_config
    assert "listen 8080;" in nginx_config
    assert "proxy_pass https://origin.multi:8443;" in nginx_config
    assert "proxy_pass https://origin.multi:8000;" in nginx_config
