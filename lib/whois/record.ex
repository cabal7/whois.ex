defmodule Whois.Record do
  alias Whois.Contact

  defstruct [
    :domain,
    :raw,
    :nameservers,
    :registrar,
    :domain_status,
    :unlocked?,
    :created_at,
    :updated_at,
    :expires_at,
    :contacts
  ]

  @type t :: %__MODULE__{
          domain: String.t(),
          raw: String.t(),
          nameservers: [String.t()],
          registrar: String.t(),
          domain_status: String.t(),
          unlocked?: bool(),
          created_at: NaiveDateTime.t(),
          updated_at: NaiveDateTime.t(),
          expires_at: NaiveDateTime.t(),
          contacts: %{
            registrant: Contact.t(),
            administrator: Contact.t(),
            technical: Contact.t()
          }
        }

  @doc """
  Parses the raw WHOIS server response in `raw` into a `%Whois.Record{}`.
  """
  @spec parse(String.t()) :: t
  def parse(raw) do
    record = %Whois.Record{
      raw: raw,
      nameservers: [],
      contacts: %{
        registrant: %Contact{},
        administrator: %Contact{},
        technical: %Contact{}
      }
    }

    record =
      raw
      |> String.split("\n")
      |> Enum.reduce(record, fn line, record ->
        line
        |> String.trim()
        |> String.split(":", parts: 2)
        |> case do
          [name, value] ->
            name = name |> String.trim() |> String.downcase()
            value = value |> String.trim()

            case name do
              "domain name" ->
                %{record | domain: value}

              #icelandic return
              "domain" ->
                %{record | domain: value}

              "name server" ->
                %{record | nameservers: record.nameservers ++ [value]}

              #icelandic return
              "nserver" ->
                %{record | nameservers: record.nameservers ++ [value]}

              "registrar" ->
                %{record | registrar: value}

              "sponsoring registrar" ->
                %{record | registrar: value}

              "domain status" ->
                %{record | domain_status: value, unlocked?: unlocked?(value)}

              "creation date" ->
                %{record | created_at: parse_dt(value) || record.created_at}

              #icelandic return
              "created" ->
                %{record | created_at: parse_dt_is(value) || record.created_at}

              "updated date" ->
                %{record | updated_at: parse_dt(value) || record.updated_at}


              "expiration date" ->
                %{record | expires_at: parse_dt(value) || record.expires_at}

              "expires" ->
                %{record | expires_at: parse_dt_is(value) || record.expires_at}

              "registry expiry date" ->
                %{record | expires_at: parse_dt(value) || record.expires_at}

              "registrant " <> name ->
                update_in(record.contacts.registrant, &parse_contact(&1, name, value))

              "admin " <> name ->
                update_in(record.contacts.administrator, &parse_contact(&1, name, value))

              "tech " <> name ->
                update_in(record.contacts.technical, &parse_contact(&1, name, value))

              _ ->
                record
            end

          _ ->
            record
        end
      end)

    nameservers =
      record.nameservers
      |> Enum.map(&String.downcase/1)
      |> Enum.uniq()

    %{record | nameservers: nameservers}
  end

  defp parse_dt(string) do
    case NaiveDateTime.from_iso8601(string) do
      {:ok, datetime} -> datetime
      {:error, _} -> nil
    end
  end

  defp parse_dt_is(string) do
    String.split(string, " ", trim: true)
    |> parse_month_is()
  end

  defp parse_month_is(["January", day, year]), do: "#{year}-01-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["February", day, year]), do: "#{year}-02-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["March", day, year]), do: "#{year}-03-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["April", day, year]), do: "#{year}-04-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["May", day, year]), do: "#{year}-05-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["June", day, year]), do: "#{year}-06-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["July", day, year]), do: "#{year}-07-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["August", day, year]), do: "#{year}-08-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["September", day, year]), do: "#{year}-09-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["October", day, year]), do: "#{year}-10-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["November", day, year]), do: "#{year}-11-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()
  defp parse_month_is(["December", day, year]), do: "#{year}-12-#{fix_day(day)}T00:00:00" |> NaiveDateTime.from_iso8601!()

  defp fix_day("1"), do: "01"
  defp fix_day("2"), do: "02"
  defp fix_day("3"), do: "03"
  defp fix_day("4"), do: "04"
  defp fix_day("5"), do: "05"
  defp fix_day("6"), do: "06"
  defp fix_day("7"), do: "07"
  defp fix_day("8"), do: "08"
  defp fix_day("9"), do: "09"
  defp fix_day(day), do: day

  defp parse_contact(%Contact{} = contact, name, value) do
    key =
      case name do
        "name" -> :name
        "organization" -> :organization
        "street" -> :street
        "city" -> :city
        "state/province" -> :state
        "postal code" -> :zip
        "country" -> :country
        "phone" -> :phone
        "fax" -> :fax
        "email" -> :email
        _ -> nil
      end

    if key do
      %{contact | key => value}
    else
      contact
    end
  end
  # https://www.icann.org/en/system/files/files/epp-status-codes-30jun11-en.pdf
  defp unlocked?("ok" <> _), do: true
  defp unlocked?(_), do: false
end

defimpl Inspect, for: Whois.Record do
  def inspect(%Whois.Record{} = record, opts) do
    record
    |> Map.put(:raw, "…")
    |> Map.delete(:__struct__)
    |> Inspect.Map.inspect("Whois.Record", opts)
  end
end
