defmodule AWS.Signature2 do

  @moduledoc """
AWS.Signature2 is an Elixir implementation of the AWS Signature
Version 2 signing process as described here: http://amzn.to/1p4Z9dS

Use it like:

  {signature, request_url, method} = 
    AWS.Signature2.sign("https://elasticmapreduce.amazonaws.com/", # URL
                        [Action: "DescribeJobFlows"],              # params
                        :GET)                                      # method

Note the trailing / on the URL -- it is not optional!
"""
  def sign(url, params, method, access \\ nil, secret \\ nil, date \\ nil) do
    access = if access == nil, do: access_key, else: access
    secret = if secret == nil, do: secret_key, else: secret
    method = to_string(method) |> String.upcase
    uri_info = URI.parse url
    ts = if date == nil, do: DateFmt.format!(Date.now, "{ISO}"), else: date
    required_params = [SignatureMethod: "HmacSHA256",
                         SignatureVersion: 2,
                         AWSAccessKeyId: access,
                         Version: "2009-03-31",
                         Timestamp: ts]
    sorted_params = params ++ required_params |> Enum.sort
    qs = params_to_qs(sorted_params)
    message = Enum.join [method, uri_info.host, uri_info.path, qs], "\n"
    sig = URI.encode_www_form(:base64.encode(:hmac.hmac256(secret, message)))
    request = "#{ url }?#{ qs }&Signature=#{ sig }"
    {sig, request, method}
  end
  def sign_papi(url, params, method, access \\ nil, secret \\ nil, date \\ nil) do
    access = if access == nil, do: access_key, else: access
    secret = if secret == nil, do: secret_key, else: secret
    method = to_string(method) |> String.upcase
    uri_info = URI.parse url
    ts = if date == nil, do: now(), else: date
    required = %{"Timestamp" =>  ts} 
    combined_params = Map.merge(params,required) |> Enum.sort
    qs = params_to_qs(combined_params)
    message = "#{method}\n#{uri_info.host}\n#{uri_info.path}\n#{qs}"
    raw_sig = :base64.encode(:hmac.hmac256(secret, message)) |> String.strip()
    sig = URI.encode_www_form(raw_sig)
    request = "#{ url }?#{ qs }&Signature=#{ sig }"
    %{signature: sig, request: request, method: method}
  end

  def secret_key, do: System.get_env("AWS_SECRET_KEY")
  def access_key, do: System.get_env("AWS_ACCESS_KEY")
  def now do
    {:ok, date} = Timex.Date.now|> Timex.DateFormat.format("{ISO}")
    date
  end

  def params_to_qs(params) do
    space = "%20"               # the AWS will not accept +, must be %20
    Regex.replace(~r/\+/, URI.encode_query(params), space)
  end

end
