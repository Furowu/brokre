class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.17"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "0f13ddf2587432fed96ff35bf8eae8fcf50275f40dc84dd2b18ea760e5c0b32f"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "1b9a180c890910160c38d1fc11f521e67fd6e55f30a413748b918a78c22230c1"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "4b38b009e8d2918d6fa604171968b0fe26f547050d0343c5de8f179de0da445b"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.17/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "98f810029e8808e2bf3033e3371d917aadf21d89734c487749b10bb64f5319ed"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
