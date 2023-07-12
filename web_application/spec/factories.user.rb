require 'factories.report'
FactoryBot.define do
    factory(:user) do
        id {"1"}
        username {"ezio"}
        email {"ezio@studenti.uniroma1.it"}
        password {"Gf2ikmcdop987"}
        roles_mask{"0"}
    end
end
