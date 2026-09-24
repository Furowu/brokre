class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.35"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.35/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "86a0682ccc6404bfb91cd768c6b17cf31c9d97a57d94070bd20b4b3048a95fd8"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.35/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "4b3a92d5d6199dcd2d939ecb166d560dc34a641b0d7728a06fb5633dbbfd9f00"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.35/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "df4848beb1e3ad7f1273d9131880f8b2f35f81c80ace5a52c1dbc04c8bb31596"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.35/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "5080e52dcafb058739735ccaaae44b7d9e9146fc75c4721754ab154843c13eb1"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
